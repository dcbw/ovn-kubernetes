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

type AddressSetIterFunc func(name, namespace, suffix string)
type AddressSetDoFunc func(as AddressSet) error

// AddressSetFactory is an interface for managing address set objects
type AddressSetFactory interface {
	// NewAddressSet returns a new object that implements NewAddressSet
	// and contains the given IPs, or an error
	NewAddressSet(name string, ips []net.IP) (AddressSet, error)
	// ForEachAddressSet calls the given function for each address set
	// known to the factory
	ForEachAddressSet(iteratorFn AddressSetIterFunc) error
	// WithAddressSet executes the passed function with the named address
	// set and returns an error or nil
	WithAddressSet(name string, doFn AddressSetDoFunc) error
	// DeleteAddressSet removes the named address set from the factory
	// and any backing storage (like OVN)
	DeleteAddressSet(name string)
}

type ovnAddressSetFactory struct {
	sync.RWMutex
	sets map[string]*ovnAddressSet
}

// NewOvnAddressSetFactory creates a new AddressSetFactory backed by
// address set objects that execute OVN commands
func NewOvnAddressSetFactory() AddressSetFactory {
	return &ovnAddressSetFactory{
		sets: make(map[string]*ovnAddressSet),
	}
}

// ovnAddressSetFactory implements the AddressSetFactory interface
var _ AddressSetFactory = &ovnAddressSetFactory{}

// NewAddressSet returns a new address set object
func (asf *ovnAddressSetFactory) NewAddressSet(name string, ips []net.IP) (AddressSet, error) {
	asf.Lock()
	defer asf.Unlock()
	if _, ok := asf.sets[name]; ok {
		klog.Errorf("address set %q already exists; overwriting", name)
	}
	as, err := newOvnAddressSet(name, ips, asf.removeAddressSet)
	if err == nil {
		asf.sets[name] = as
	}
	return as, err
}

// ForEachAddressSet will pass the unhashedName, namespaceName and
// the first suffix in the name to the 'iteratorFn' for every address_set in
// OVN. (Each unhashed name for an ovnAddressSet can be of the form
// namespaceName.suffix1.suffix2. .suffixN)
func (asf *ovnAddressSetFactory) ForEachAddressSet(iteratorFn AddressSetIterFunc) error {
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

func (asf *ovnAddressSetFactory) getAddressSet(name string) *ovnAddressSet {
	asf.RLock()
	defer asf.RUnlock()
	if as := asf.sets[name]; as != nil {
		as.Lock()
		return as
	}
	return nil
}

func (asf *ovnAddressSetFactory) WithAddressSet(name string, doFn AddressSetDoFunc) error {
	if as := asf.getAddressSet(name); as != nil {
		defer as.Unlock()
		return doFn(as)
	}
	return nil
}

// removeAddressSet removes the address set from the factory
func (asf *ovnAddressSetFactory) removeAddressSet(name string) {
	asf.Lock()
	defer asf.Unlock()
	delete(asf.sets, name)
}

func (asf *ovnAddressSetFactory) DeleteAddressSet(name string) {
	if as := asf.getAddressSet(name); as != nil {
		defer as.Unlock()
		as.destroyUnlocked()
	} else {
		_, stderr, err := util.RunOVNNbctl("--if-exists", "destroy", "address_set", hashedAddressSet(name))
		if err != nil {
			klog.Errorf("failed to destroy address set %q, stderr: %q, (%v)", name, stderr, err)
		}
	}
}

// AddressSet is an interface for address set objects. If the function name
// does not contain "Unlocked" the function
type AddressSet interface {
	// GetHashName returns the hashed name of the address set
	GetHashName() string
	// GetName returns the descriptive name of the address set
	GetName() string
	AddIPUnlocked(ip net.IP) error
	AddIP(ip net.IP) error
	DeleteIPUnlocked(ip net.IP) error
	DeleteIP(ip net.IP) error
	Destroy()
}

type removeFunc func(string)

type ovnAddressSet struct {
	sync.RWMutex
	name     string
	hashName string
	uuid     string
	ips      map[string]net.IP
	removeFn removeFunc
}

// ovnAddressSet implements the AddressSet interface
var _ AddressSet = &ovnAddressSet{}

// hash the provided input to make it a valid ovnAddressSet name.
func hashedAddressSet(s string) string {
	return hashForOVN(s)
}

func newOvnAddressSet(name string, ips []net.IP, removeFn removeFunc) (*ovnAddressSet, error) {
	as := &ovnAddressSet{
		name:     name,
		hashName: hashedAddressSet(name),
		ips:      make(map[string]net.IP),
		removeFn: removeFn,
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

	// ovnAddressSet has already been created in the database and nothing to set.
	if uuid != "" {
		if err := as.setOrClear(); err != nil {
			return nil, err
		}
	} else {
		// ovnAddressSet has not been created yet. Create it.
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

func (as *ovnAddressSet) GetHashName() string {
	return as.hashName
}

func (as *ovnAddressSet) GetName() string {
	return as.name
}

func (as *ovnAddressSet) joinIPs() string {
	list := make([]string, 0, len(as.ips))
	for ipStr := range as.ips {
		list = append(list, `"`+ipStr+`"`)
	}
	sort.Strings(list)
	return strings.Join(list, " ")
}

// setOrClear updates the OVN database with the address set's addresses or
// clears the address set if there are no addresses in the address set
func (as *ovnAddressSet) setOrClear() error {
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

func (as *ovnAddressSet) AddIPUnlocked(ip net.IP) error {
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

func (as *ovnAddressSet) AddIP(ip net.IP) error {
	as.Lock()
	defer as.Unlock()
	return as.AddIPUnlocked(ip)
}

func (as *ovnAddressSet) DeleteIPUnlocked(ip net.IP) error {
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

func (as *ovnAddressSet) DeleteIP(ip net.IP) error {
	as.Lock()
	defer as.Unlock()
	return as.DeleteIPUnlocked(ip)
}

func (as *ovnAddressSet) destroyUnlocked() {
	klog.V(5).Infof("Destroy(%s/%s)", as.uuid, as.name)
	_, stderr, err := util.RunOVNNbctl("--if-exists", "destroy", "address_set", as.uuid)
	if err != nil {
		klog.Errorf("failed to destroy address set %q, stderr: %q, (%v)", as.uuid, stderr, err)
	}
	as.removeFn(as.name)
}

func (as *ovnAddressSet) Destroy() {
	as.Lock()
	defer as.Unlock()
	as.destroyUnlocked()
}
