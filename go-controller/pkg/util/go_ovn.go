package util

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"syscall"

	goovn "github.com/ebay/go-ovn"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"k8s.io/klog"
)

type OVNClient struct {
	client goovn.Client
}

var _ OVNInterface = &OVNClient{}

func NewOVNNBDBClient() (OVNInterface, error) {
	var (
		err         error
		ovnNBClient *OVNClient
	)

	ovnNBClient = &OVNClient{}

	switch config.OvnNorth.Scheme {
	case config.OvnDBSchemeSSL:
		ovnNBClient.client, err = initGoOvnSslClient(config.OvnNorth.Cert,
			config.OvnNorth.PrivKey, config.OvnNorth.CACert,
			config.OvnNorth.GetURL(), goovn.DBNB, config.OvnNorth.CertCommonName)
	case config.OvnDBSchemeTCP:
		ovnNBClient.client, err = initGoOvnTcpClient(config.OvnNorth.GetURL(), goovn.DBNB)
	case config.OvnDBSchemeUnix:
		ovnNBClient.client, err = initGoOvnUnixClient(config.OvnNorth.GetURL(), goovn.DBNB)
	default:
		klog.Errorf("Invalid db scheme: %s when initializing the OVN NB Client",
			config.OvnNorth.Scheme)
	}

	if err != nil {
		return nil, fmt.Errorf("couldn't initialize NBDB client: %s", err)
	}

	klog.Infof("Created OVN NB client with Scheme: %s", config.OvnNorth.Scheme)
	return ovnNBClient, nil
}

func NewOVNSBDBClient() (OVNInterface, error) {
	var (
		err         error
		ovnSBClient *OVNClient
	)

	ovnSBClient = &OVNClient{}

	switch config.OvnSouth.Scheme {

	case config.OvnDBSchemeSSL:
		ovnSBClient.client, err = initGoOvnSslClient(config.OvnSouth.Cert,
			config.OvnSouth.PrivKey, config.OvnSouth.CACert,
			config.OvnSouth.GetURL(), goovn.DBSB, config.OvnSouth.CertCommonName)
	case config.OvnDBSchemeTCP:
		ovnSBClient.client, err = initGoOvnTcpClient(config.OvnSouth.GetURL(), goovn.DBSB)
	case config.OvnDBSchemeUnix:
		ovnSBClient.client, err = initGoOvnUnixClient(config.OvnSouth.GetURL(), goovn.DBSB)
	default:
		klog.Errorf("Invalid db scheme: %s when initializing the OVN SB Client",
			config.OvnSouth.Scheme)
	}

	if err != nil {
		return nil, fmt.Errorf("couldn't initialize SBDB client: %s", err)
	}

	klog.Infof("Created OVN SB client with Scheme: %s", config.OvnSouth.Scheme)
	return ovnSBClient, nil
}

func initGoOvnSslClient(certFile, privKeyFile, caCertFile, address, db, serverName string) (goovn.Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, privKeyFile)
	if err != nil {
		return nil, fmt.Errorf("error generating x509 certs for ovndbapi: %s", err)
	}
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("error generating ca certs for ovndbapi: %s", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   serverName,
	}
	tlsConfig.BuildNameToCertificate()
	ovndbclient, err := goovn.NewClient(&goovn.Config{
		Db:        db,
		Addr:      address,
		TLSConfig: tlsConfig,
		Reconnect: true,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating SSL OVNDBClient for database %s at address %s: %s", db, address, err)
	}
	klog.Infof("Created OVNDB SSL client for db: %s", db)
	return ovndbclient, nil
}

func initGoOvnTcpClient(address, db string) (goovn.Client, error) {
	ovndbclient, err := goovn.NewClient(&goovn.Config{
		Db:        db,
		Addr:      address,
		Reconnect: true,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating TCP OVNDBClient for address %s: %s", address, err)
	}
	klog.Infof("Created OVNDB TCP client for db: %s", db)
	return ovndbclient, nil
}

func initGoOvnUnixClient(address, db string) (goovn.Client, error) {
	ovndbclient, err := goovn.NewClient(&goovn.Config{
		Db:        db,
		Addr:      address,
		Reconnect: true,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating UNIX OVNDBClient for address %s: %s", address, err)
	}
	klog.Infof("Created OVNDB UNIX client for db: %s", db)
	return ovndbclient, nil
}

// Client Interface Methods

// Get logical switch by name
func (ovnclient *OVNClient) LSGet(ls string) ([]*goovn.LogicalSwitch, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSGet(ls)
}

// Create ls named SWITCH
func (ovnclient *OVNClient) LSAdd(ls string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSAdd(ls)
}

// Del ls and all its ports
func (ovnclient *OVNClient) LSDel(ls string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSDel(ls)
}

// Get all logical switches
func (ovnclient *OVNClient) LSList() ([]*goovn.LogicalSwitch, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSList()
}

// Add external_ids to logical switch
func (ovnclient *OVNClient) LSExtIdsAdd(ls string, external_ids map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSExtIdsAdd(ls, external_ids)
}

// Del external_ids from logical_switch
func (ovnclient *OVNClient) LSExtIdsDel(ls string, external_ids map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSExtIdsDel(ls, external_ids)
}

// Link logical switch to router
func (ovnclient *OVNClient) LinkSwitchToRouter(lsw, lsp, lr, lrp, lrpMac string, networks []string, externalIds map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LinkSwitchToRouter(lsw, lsp, lr, lrp, lrpMac, networks, externalIds)
}

// Get logical switch port by name
func (ovnclient *OVNClient) LSPGet(lsp string) (*goovn.LogicalSwitchPort, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPGet(lsp)
}

// Add logical port PORT on SWITCH
func (ovnclient *OVNClient) LSPAdd(ls string, lsp string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPAdd(ls, lsp)
}

// Delete PORT from its attached switch
func (ovnclient *OVNClient) LSPDel(lsp string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPDel(lsp)
}

// Set addressset per lport
func (ovnclient *OVNClient) LSPSetAddress(lsp string, addresses ...string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPSetAddress(lsp, addresses...)
}

// Set port security per lport
func (ovnclient *OVNClient) LSPSetPortSecurity(lsp string, security ...string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPSetPortSecurity(lsp, security...)
}

// Get all lport by lswitch
func (ovnclient *OVNClient) LSPList(ls string) ([]*goovn.LogicalSwitchPort, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPList(ls)
}

// Add LB to LSW
func (ovnclient *OVNClient) LSLBAdd(ls string, lb string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSLBAdd(ls, lb)
}

// Delete LB from LSW
func (ovnclient *OVNClient) LSLBDel(ls string, lb string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSLBDel(ls, lb)
}

// List Load balancers for a LSW
func (ovnclient *OVNClient) LSLBList(ls string) ([]*goovn.LoadBalancer, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSLBList(ls)
}

// Add ACL
func (ovnclient *OVNClient) ACLAdd(ls, direct, match, action string, priority int, external_ids map[string]string, logflag bool, meter string, severity string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.ACLAdd(ls, direct, match, action, priority, external_ids, logflag, meter, severity)
}

// Delete acl
func (ovnclient *OVNClient) ACLDel(ls, direct, match string, priority int, external_ids map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.ACLDel(ls, direct, match, priority, external_ids)
}

// Get all acl by lswitch
func (ovnclient *OVNClient) ACLList(ls string) ([]*goovn.ACL, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.ACLList(ls)
}

// Get AS
func (ovnclient *OVNClient) ASGet(name string) (*goovn.AddressSet, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.ASGet(name)
}

// Update address set
func (ovnclient *OVNClient) ASUpdate(name string, addrs []string, external_ids map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.ASUpdate(name, addrs, external_ids)
}

// Add addressset
func (ovnclient *OVNClient) ASAdd(name string, addrs []string, external_ids map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.ASAdd(name, addrs, external_ids)
}

// Delete addressset
func (ovnclient *OVNClient) ASDel(name string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.ASDel(name)
}

// Get all AS
func (ovnclient *OVNClient) ASList() ([]*goovn.AddressSet, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.ASList()
}

// Get LR with given name
func (ovnclient *OVNClient) LRGet(name string) ([]*goovn.LogicalRouter, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRGet(name)
}

// Add LR with given name
func (ovnclient *OVNClient) LRAdd(name string, external_ids map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRAdd(name, external_ids)
}

// Delete LR with given name
func (ovnclient *OVNClient) LRDel(name string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRDel(name)
}

// Get LRs
func (ovnclient *OVNClient) LRList() ([]*goovn.LogicalRouter, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRList()
}

// Add LRP with given name on given lr
func (ovnclient *OVNClient) LRPAdd(lr string, lrp string, mac string, network []string, peer string, external_ids map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRPAdd(lr, lrp, mac, network, peer, external_ids)
}

// Delete LRP with given name on given lr
func (ovnclient *OVNClient) LRPDel(lr string, lrp string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRPDel(lr, lrp)
}

// Get all lrp by lr
func (ovnclient *OVNClient) LRPList(lr string) ([]*goovn.LogicalRouterPort, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRPList(lr)
}

// Add LRSR with given ip_prefix on given lr
func (ovnclient *OVNClient) LRSRAdd(lr string, ip_prefix string, nexthop string, output_port []string, policy []string, external_ids map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRSRAdd(lr, ip_prefix, nexthop, output_port, policy, external_ids)
}

// Delete LRSR with given ip_prefix on given lr
func (ovnclient *OVNClient) LRSRDel(lr string, ip_prefix string, nexthop, policy, outputPort *string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRSRDel(lr, ip_prefix, nexthop, policy, outputPort)
}

// Get all LRSRs by lr
func (ovnclient *OVNClient) LRSRList(lr string) ([]*goovn.LogicalRouterStaticRoute, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRSRList(lr)
}

// Add LB to LR
func (ovnclient *OVNClient) LRLBAdd(lr string, lb string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRLBAdd(lr, lb)
}

// Delete LB from LR
func (ovnclient *OVNClient) LRLBDel(lr string, lb string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRLBDel(lr, lb)
}

// List Load balancers for a LR
func (ovnclient *OVNClient) LRLBList(lr string) ([]*goovn.LoadBalancer, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRLBList(lr)
}

// Get LB with given name
func (ovnclient *OVNClient) LBGet(name string) ([]*goovn.LoadBalancer, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LBGet(name)
}

// Add LB
func (ovnclient *OVNClient) LBAdd(name string, vipPort string, protocol string, addrs []string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LBAdd(name, vipPort, protocol, addrs)
}

// Delete LB with given name
func (ovnclient *OVNClient) LBDel(name string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LBDel(name)
}

// Update existing LB
func (ovnclient *OVNClient) LBUpdate(name string, vipPort string, protocol string, addrs []string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LBUpdate(name, vipPort, protocol, addrs)
}

// Set dhcp4_options uuid on lsp
func (ovnclient *OVNClient) LSPSetDHCPv4Options(lsp string, options string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPSetDHCPv4Options(lsp, options)
}

// Get dhcp4_options from lsp
func (ovnclient *OVNClient) LSPGetDHCPv4Options(lsp string) (*goovn.DHCPOptions, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPGetDHCPv4Options(lsp)
}

// Set dhcp6_options uuid on lsp
func (ovnclient *OVNClient) LSPSetDHCPv6Options(lsp string, options string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPSetDHCPv6Options(lsp, options)
}

// Get dhcp6_options from lsp
func (ovnclient *OVNClient) LSPGetDHCPv6Options(lsp string) (*goovn.DHCPOptions, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPGetDHCPv6Options(lsp)
}

// Set options in LSP
func (ovnclient *OVNClient) LSPSetOptions(lsp string, options map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPSetOptions(lsp, options)
}

// Get Options for LSP
func (ovnclient *OVNClient) LSPGetOptions(lsp string) (map[string]string, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPGetOptions(lsp)
}

// Set dynamic addresses in LSP
func (ovnclient *OVNClient) LSPSetDynamicAddresses(lsp string, address string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPSetDynamicAddresses(lsp, address)
}

// Get dynamic addresses from LSP
func (ovnclient *OVNClient) LSPGetDynamicAddresses(lsp string) (string, error) {
	if ovnclient.client == nil {
		return "", syscall.ENOTCONN
	}
	return ovnclient.client.LSPGetDynamicAddresses(lsp)
}

// Set external_ids for LSP
func (ovnclient *OVNClient) LSPSetExternalIds(lsp string, external_ids map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPSetExternalIds(lsp, external_ids)
}

// Get external_ids from LSP
func (ovnclient *OVNClient) LSPGetExternalIds(lsp string) (map[string]string, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LSPGetExternalIds(lsp)
}

// Add dhcp options for cidr and provided external_ids
func (ovnclient *OVNClient) DHCPOptionsAdd(cidr string, options map[string]string, external_ids map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.DHCPOptionsAdd(cidr, options, external_ids)
}

// Set dhcp options and set external_ids for specific uuid
func (ovnclient *OVNClient) DHCPOptionsSet(uuid string, options map[string]string, external_ids map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.DHCPOptionsSet(uuid, options, external_ids)
}

// Del dhcp options via provided external_ids
func (ovnclient *OVNClient) DHCPOptionsDel(uuid string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.DHCPOptionsDel(uuid)
}

// Get single dhcp via provided uuid
func (ovnclient *OVNClient) DHCPOptionsGet(uuid string) (*goovn.DHCPOptions, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.DHCPOptionsGet(uuid)
}

// List dhcp options
func (ovnclient *OVNClient) DHCPOptionsList() ([]*goovn.DHCPOptions, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.DHCPOptionsList()
}

// Add qos rule
func (ovnclient *OVNClient) QoSAdd(ls string, direction string, priority int, match string, action map[string]int, bandwidth map[string]int, external_ids map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.QoSAdd(ls, direction, priority, match, action, bandwidth, external_ids)
}

// Del qos rule, to delete wildcard specify priority -1 and string options as ""
func (ovnclient *OVNClient) QoSDel(ls string, direction string, priority int, match string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.QoSDel(ls, direction, priority, match)
}

// Get qos rules by logical switch
func (ovnclient *OVNClient) QoSList(ls string) ([]*goovn.QoS, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.QoSList(ls)
}

//Add NAT to Logical Router
func (ovnclient *OVNClient) LRNATAdd(lr string, ntype string, externalIp string, logicalIp string, external_ids map[string]string, logicalPortAndExternalMac ...string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRNATAdd(lr, ntype, externalIp, logicalIp, external_ids, logicalPortAndExternalMac...)
}

//Del NAT from Logical Router
func (ovnclient *OVNClient) LRNATDel(lr string, ntype string, ip ...string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRNATDel(lr, ntype, ip...)
}

// Get NAT List by Logical Router
func (ovnclient *OVNClient) LRNATList(lr string) ([]*goovn.NAT, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.LRNATList(lr)
}

// Add Meter with a Meter Band
func (ovnclient *OVNClient) MeterAdd(name, action string, rate int, unit string, external_ids map[string]string, burst int) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.MeterAdd(name, action, rate, unit, external_ids, burst)
}

// Deletes meters
func (ovnclient *OVNClient) MeterDel(name ...string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.MeterDel(name...)
}

// List Meters
func (ovnclient *OVNClient) MeterList() ([]*goovn.Meter, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.MeterList()
}

// List Meter Bands
func (ovnclient *OVNClient) MeterBandsList() ([]*goovn.MeterBand, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.MeterBandsList()
}

// Exec command, support mul-commands in one transaction.
func (ovnclient *OVNClient) Execute(cmds ...OVNCommandInterface) error {
	if ovnclient.client == nil {
		return syscall.ENOTCONN
	}
	ovnCmds := make([]*goovn.OvnCommand, 0, len(cmds))
	for _, cmd := range cmds {
		ovnCmd, ok := cmd.(*goovn.OvnCommand)
		if !ok {
			return fmt.Errorf("type assertion for OvnCommand failed")
		}
		ovnCmds = append(ovnCmds, ovnCmd)
	}
	return ovnclient.client.Execute(ovnCmds...)
}

// Add chassis with given name
func (ovnclient *OVNClient) ChassisAdd(name string, hostname string, etype []string, ip string, external_ids map[string]string,
	transport_zones []string, vtep_lswitches []string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.ChassisAdd(name, hostname, etype, ip, external_ids, transport_zones, vtep_lswitches)
}

// Delete chassis with given name
func (ovnclient *OVNClient) ChassisDel(chName string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.ChassisDel(chName)
}

// Get chassis by hostname or name
func (ovnclient *OVNClient) ChassisGet(chname string) ([]*goovn.Chassis, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.ChassisGet(chname)
}

// Get encaps by chassis name
func (ovnclient *OVNClient) EncapList(chname string) ([]*goovn.Encap, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.EncapList(chname)
}

// Set NB_Global table options
func (ovnclient *OVNClient) NBGlobalSetOptions(options map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.NBGlobalSetOptions(options)
}

// Get NB_Global table options
func (ovnclient *OVNClient) NBGlobalGetOptions() (map[string]string, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.NBGlobalGetOptions()
}

// Set SB_Global table options
func (ovnclient *OVNClient) SBGlobalSetOptions(options map[string]string) (OVNCommandInterface, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.SBGlobalSetOptions(options)
}

// Get SB_Global table options
func (ovnclient *OVNClient) SBGlobalGetOptions() (map[string]string, error) {
	if ovnclient.client == nil {
		return nil, syscall.ENOTCONN
	}
	return ovnclient.client.SBGlobalGetOptions()
}

// Close connection to OVN
func (ovnclient *OVNClient) Close() error {
	if ovnclient.client == nil {
		return syscall.ENOTCONN
	}
	return ovnclient.client.Close()
}
