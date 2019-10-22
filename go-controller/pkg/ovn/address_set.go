package ovn

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"k8s.io/klog"
)

type addressSet struct {
	sync.Mutex
	name     string
	hashName string
	uuid     string
	ips      map[string]net.IP
}

// hash the provided input to make it a valid addressSet name.
func hashedAddressSet(s string) string {
	return hashForOVN(s)
}

type addressSetIterFn func(name, namespace, suffix string)

// forEachAddressSetUnhashedName will pass the unhashedName, namespaceName and
// the first suffix in the name to the 'iteratorFn' for every address_set in
// OVN. (Each unhashed name for an addressSet can be of the form
// namespaceName.suffix1.suffix2. .suffixN)
func forEachAddressSetUnhashedName(iteratorFn addressSetIterFn) error {
	output, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=external_ids", "find", "address_set")
	if err != nil {
		return fmt.Errorf("error reading address sets: "+
			"stdout: %q, stderr: %q err: %v", output, stderr, err)
	}
	for _, addrSet := range strings.Fields(output) {
		if !strings.HasPrefix(addrSet, "name=") {
			continue
		}
		addrSetName := addrSet[5:]
		names := strings.Split(addrSetName, ".")
		addrSetNamespace := names[0]
		nameSuffix := ""
		if len(names) >= 2 {
			nameSuffix = names[1]
		}
		iteratorFn(addrSetName, addrSetNamespace, nameSuffix)
	}
	return nil
}

func NewAddressSet(name string, ips []net.IP) (*addressSet, error) {
	as := &addressSet{
		name:     name,
		hashName: hashedAddressSet(name),
		ips:      make(map[string]net.IP),
	}
	for _, ip := range ips {
		as.ips[ip.String()] = ip
	}

	uuid, stderr, err := util.RunOVNNbctl("--data=bare",
		"--no-heading", "--columns=_uuid", "find", "address_set",
		"name="+as.hashName)
	if err != nil {
		return nil, fmt.Errorf("find failed to get address set %q, stderr: %q (%v)",
			as.name, stderr, err)
	}
	as.uuid = uuid

	// addressSet has already been created in the database and nothing to set.
	if uuid != "" {
		if err := as.setOrClear(); err != nil {
			return nil, err
		}
	} else {
		// addressSet has not been created yet. Create it.
		args := []string{
			"create",
			"address_set",
			"name=" + as.hashName,
			"external-ids:name=" + as.name,
		}
		joinedIPs := as.joinIPs()
		if len(joinedIPs) > 0 {
			args = append(args, "addresses="+joinedIPs)
		}
		as.uuid, stderr, err = util.RunOVNNbctl(args...)
		if err != nil {
			return nil, fmt.Errorf("failed to create address set %q, stderr: %q (%v)",
				as.name, stderr, err)
		}
	}

	klog.V(5).Infof("New(%s/%s) hashName %q with %v", as.uuid, as.name, as.hashName, ips)

	return as, nil
}

func (as *addressSet) joinIPs() string {
	list := make([]string, 0, len(as.ips))
	for ipStr := range as.ips {
		list = append(list, `"`+ipStr+`"`)
	}
	sort.Strings(list)
	return strings.Join(list, " ")
}

// setOrClear updates the OVN database with the address set's addresses or
// clears the address set if there are no addresses in the address set
func (as *addressSet) setOrClear() error {
	joinedIPs := as.joinIPs()
	if len(joinedIPs) > 0 {
		_, stderr, err := util.RunOVNNbctl("set", "address_set", as.uuid, "addresses="+joinedIPs)
		if err != nil {
			return fmt.Errorf("failed to set address set %q, stderr: %q (%v)",
				as.name, stderr, err)
		}
	} else {
		_, stderr, err := util.RunOVNNbctl("clear", "address_set", as.uuid, "addresses")
		if err != nil {
			return fmt.Errorf("failed to clear address set %q, stderr: %q (%v)",
				as.name, stderr, err)
		}
	}
	return nil
}

// ReplaceIPs replaces all the IPs of the address set. Caller must hold the
// address set lock
func (as *addressSet) ReplaceIPs(ips []net.IP) error {
	klog.V(5).Infof("ReplaceIPs(%s/%s) with %v", as.uuid, as.name, ips)
	as.ips = make(map[string]net.IP)
	for _, ip := range ips {
		as.ips[ip.String()] = ip
	}
	return as.setOrClear()
}

func (as *addressSet) AddIPUnlocked(ip net.IP) error {
	ipStr := ip.String()
	if _, ok := as.ips[ipStr]; ok {
		return nil
	}

	klog.V(5).Infof("AddIP(%s/%s) %s", as.uuid, as.name, ipStr)
	as.ips[ip.String()] = ip

	_, stderr, err := util.RunOVNNbctl("add", "address_set", as.uuid, "addresses", `"`+ipStr+`"`)
	if err != nil {
		return fmt.Errorf("failed to add address %q to address_set %q, stderr: %q (%v)",
			ip, as.uuid, stderr, err)
	}
	return nil
}

func (as *addressSet) AddIP(ip net.IP) error {
	as.Lock()
	defer as.Unlock()
	return as.AddIPUnlocked(ip)
}

func (as *addressSet) DeleteIPUnlocked(ip net.IP) error {
	ipStr := ip.String()
	if _, ok := as.ips[ipStr]; !ok {
		return nil
	}

	klog.V(5).Infof("DeleteIP(%s/%s) %s", as.uuid, as.name, ipStr)
	delete(as.ips, ipStr)

	_, stderr, err := util.RunOVNNbctl("remove", "address_set", as.uuid, "addresses", `"`+ipStr+`"`)
	if err != nil {
		return fmt.Errorf("failed to remove address %q from address_set %q, stderr: %q (%v)",
			ip, as.uuid, stderr, err)
	}
	return nil
}

func (as *addressSet) DeleteIP(ip net.IP) error {
	as.Lock()
	defer as.Unlock()
	return as.DeleteIPUnlocked(ip)
}

func (as *addressSet) DestroyUnlocked() {
	klog.V(5).Infof("Destroy(%s/%s)", as.uuid, as.name)
	_, stderr, err := util.RunOVNNbctl("--if-exists", "destroy", "address_set", as.uuid)
	if err != nil {
		klog.Errorf("failed to destroy address set %q, stderr: %q, (%v)", as.uuid, stderr, err)
	}
}

func (as *addressSet) Destroy() {
	as.Lock()
	defer as.Unlock()
	as.DestroyUnlocked()
}
