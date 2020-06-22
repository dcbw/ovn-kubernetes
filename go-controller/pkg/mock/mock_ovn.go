package mockovn

import (
	"fmt"
	"runtime"

	goovn "github.com/ebay/go-ovn"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	aggErrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog"
)

const (
	LogicalSwitchType     string = "Logical_Switch"
	LogicalSwitchPortType string = "Logical_Switch_Port"
)

const (
	OpAdd    string = "Add"
	OpDelete string = "Delete"
	OpUpdate string = "Update"
)

// used to update fields for existing objects in mock cache
type UpdateCache struct {
	FieldType  string
	FieldValue interface{}
}

// object cache for mock ovn client
type MockObjectCacheByName map[string]interface{}

// provides Execute() interface
type MockExecution interface {
	Execute(cmds ...util.OVNCommandInterface) error
}

// mock ovn client for testing
type MockOVNClient struct {
	db string
	// cache holds ovn db rows by table name as the key
	cache map[string]MockObjectCacheByName
	// error injection
	// keys are of the form: Table:Name:FieldType
	errorCache map[string]error
}

var _ util.OVNInterface = &MockOVNClient{}

type MockOVNCommand struct {
	Exe       MockExecution
	op        string
	table     string
	objName   string
	obj       interface{}
	objUpdate UpdateCache
}

// MockOVNCommand implements OVNCommandInterface
var _ util.OVNCommandInterface = &MockOVNCommand{}

// return a new mock client to operate on db
func NewMockOVNClient(db string) *MockOVNClient {
	return &MockOVNClient{
		db:         db,
		cache:      make(map[string]MockObjectCacheByName),
		errorCache: make(map[string]error),
	}
}

func functionName() string {
	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		return "???"
	}

	fn := runtime.FuncForPC(pc)
	return fn.Name()
}

// Client Interface Methods

// TODO: implement mock methods as we keep adding unit-tests
// Get logical switch by name
func (mock *MockOVNClient) LSGet(ls string) ([]*goovn.LogicalSwitch, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Create ls named SWITCH
func (mock *MockOVNClient) LSAdd(ls string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Del ls and all its ports
func (mock *MockOVNClient) LSDel(ls string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get all logical switches
func (mock *MockOVNClient) LSList() ([]*goovn.LogicalSwitch, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add external_ids to logical switch
func (mock *MockOVNClient) LSExtIdsAdd(ls string, external_ids map[string]string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Del external_ids from logical_switch
func (mock *MockOVNClient) LSExtIdsDel(ls string, external_ids map[string]string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Link logical switch to router
func (mock *MockOVNClient) LinkSwitchToRouter(lsw, lsp, lr, lrp, lrpMac string, networks []string, externalIds map[string]string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add LB to LSW
func (mock *MockOVNClient) LSLBAdd(ls string, lb string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete LB from LSW
func (mock *MockOVNClient) LSLBDel(ls string, lb string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// List Load balancers for a LSW
func (mock *MockOVNClient) LSLBList(ls string) ([]*goovn.LoadBalancer, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add ACL
func (mock *MockOVNClient) ACLAdd(ls, direct, match, action string, priority int, external_ids map[string]string, logflag bool, meter string, severity string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete acl
func (mock *MockOVNClient) ACLDel(ls, direct, match string, priority int, external_ids map[string]string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get all acl by lswitch
func (mock *MockOVNClient) ACLList(ls string) ([]*goovn.ACL, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get AS
func (mock *MockOVNClient) ASGet(name string) (*goovn.AddressSet, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Update address set
func (mock *MockOVNClient) ASUpdate(name string, addrs []string, external_ids map[string]string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add addressset
func (mock *MockOVNClient) ASAdd(name string, addrs []string, external_ids map[string]string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete addressset
func (mock *MockOVNClient) ASDel(name string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get all AS
func (mock *MockOVNClient) ASList() ([]*goovn.AddressSet, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get LR with given name
func (mock *MockOVNClient) LRGet(name string) ([]*goovn.LogicalRouter, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add LR with given name
func (mock *MockOVNClient) LRAdd(name string, external_ids map[string]string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete LR with given name
func (mock *MockOVNClient) LRDel(name string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get LRs
func (mock *MockOVNClient) LRList() ([]*goovn.LogicalRouter, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add LRP with given name on given lr
func (mock *MockOVNClient) LRPAdd(lr string, lrp string, mac string, network []string, peer string, external_ids map[string]string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete LRP with given name on given lr
func (mock *MockOVNClient) LRPDel(lr string, lrp string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get all lrp by lr
func (mock *MockOVNClient) LRPList(lr string) ([]*goovn.LogicalRouterPort, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add LRSR with given ip_prefix on given lr
func (mock *MockOVNClient) LRSRAdd(lr string, ip_prefix string, nexthop string, output_port []string, policy []string, external_ids map[string]string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete LRSR with given ip_prefix on given lr
func (mock *MockOVNClient) LRSRDel(lr string, ip_prefix string, nexthop, policy, outputPort *string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get all LRSRs by lr
func (mock *MockOVNClient) LRSRList(lr string) ([]*goovn.LogicalRouterStaticRoute, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add LB to LR
func (mock *MockOVNClient) LRLBAdd(lr string, lb string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete LB from LR
func (mock *MockOVNClient) LRLBDel(lr string, lb string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// List Load balancers for a LR
func (mock *MockOVNClient) LRLBList(lr string) ([]*goovn.LoadBalancer, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get LB with given name
func (mock *MockOVNClient) LBGet(name string) ([]*goovn.LoadBalancer, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add LB
func (mock *MockOVNClient) LBAdd(name string, vipPort string, protocol string, addrs []string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete LB with given name
func (mock *MockOVNClient) LBDel(name string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Update existing LB
func (mock *MockOVNClient) LBUpdate(name string, vipPort string, protocol string, addrs []string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add dhcp options for cidr and provided external_ids
func (mock *MockOVNClient) DHCPOptionsAdd(cidr string, options map[string]string, external_ids map[string]string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Set dhcp options and set external_ids for specific uuid
func (mock *MockOVNClient) DHCPOptionsSet(uuid string, options map[string]string, external_ids map[string]string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Del dhcp options via provided external_ids
func (mock *MockOVNClient) DHCPOptionsDel(uuid string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get single dhcp via provided uuid
func (mock *MockOVNClient) DHCPOptionsGet(uuid string) (*goovn.DHCPOptions, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// List dhcp options
func (mock *MockOVNClient) DHCPOptionsList() ([]*goovn.DHCPOptions, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add qos rule
func (mock *MockOVNClient) QoSAdd(ls string, direction string, priority int, match string, action map[string]int, bandwidth map[string]int, external_ids map[string]string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Del qos rule, to delete wildcard specify priority -1 and string options as ""
func (mock *MockOVNClient) QoSDel(ls string, direction string, priority int, match string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get qos rules by logical switch
func (mock *MockOVNClient) QoSList(ls string) ([]*goovn.QoS, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

//Add NAT to Logical Router
func (mock *MockOVNClient) LRNATAdd(lr string, ntype string, externalIp string, logicalIp string, external_ids map[string]string, logicalPortAndExternalMac ...string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

//Del NAT from Logical Router
func (mock *MockOVNClient) LRNATDel(lr string, ntype string, ip ...string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get NAT List by Logical Router
func (mock *MockOVNClient) LRNATList(lr string) ([]*goovn.NAT, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add Meter with a Meter Band
func (mock *MockOVNClient) MeterAdd(name, action string, rate int, unit string, external_ids map[string]string, burst int) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Deletes meters
func (mock *MockOVNClient) MeterDel(name ...string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// List Meters
func (mock *MockOVNClient) MeterList() ([]*goovn.Meter, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// List Meter Bands
func (mock *MockOVNClient) MeterBandsList() ([]*goovn.MeterBand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add chassis with given name
func (mock *MockOVNClient) ChassisAdd(name string, hostname string, etype []string, ip string, external_ids map[string]string,
	transport_zones []string, vtep_lswitches []string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete chassis with given name
func (mock *MockOVNClient) ChassisDel(chName string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get chassis by hostname or name
func (mock *MockOVNClient) ChassisGet(chname string) ([]*goovn.Chassis, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get encaps by chassis name
func (mock *MockOVNClient) EncapList(chname string) ([]*goovn.Encap, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Set NB_Global table options
func (mock *MockOVNClient) NBGlobalSetOptions(options map[string]string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get NB_Global table options
func (mock *MockOVNClient) NBGlobalGetOptions() (map[string]string, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Set SB_Global table options
func (mock *MockOVNClient) SBGlobalSetOptions(options map[string]string) (util.OVNCommandInterface, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get SB_Global table options
func (mock *MockOVNClient) SBGlobalGetOptions() (map[string]string, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Close connection to OVN
func (mock *MockOVNClient) Close() error {
	return nil
}

// Exec command, support multiple commands in one transaction.
// executes commands ensuring their temporal consistency
func (mock *MockOVNClient) Execute(cmds ...util.OVNCommandInterface) error {
	errors := make([]error, 0, len(cmds))
	for _, cmd := range cmds {
		// go over each mock command and apply the
		// individual command's operations to the
		// cache
		ovnCmd, ok := cmd.(*MockOVNCommand)
		if !ok {
			klog.Errorf("type assertion failed for mock command")
			errors = append(errors, fmt.Errorf("type assertion failed for mock command"))
		}
		var cache MockObjectCacheByName
		switch ovnCmd.op {
		case OpAdd:
			if cache, ok = mock.cache[ovnCmd.table]; !ok {
				cache = make(MockObjectCacheByName)
				mock.cache[ovnCmd.table] = cache
			}
			if _, exists := cache[ovnCmd.objName]; exists {
				errors = append(errors,
					fmt.Errorf("object %s of type %s exists in cache", ovnCmd.objName, ovnCmd.table))
			}
			cache[ovnCmd.objName] = ovnCmd.obj
		case OpDelete:
			if cache, ok = mock.cache[ovnCmd.table]; !ok {
				errors = append(errors,
					fmt.Errorf("command to delete entry from %s when cache doesn't exist", ovnCmd.table))
				continue
			}
			delete(cache, ovnCmd.objName)
		case OpUpdate:
			if cache, ok = mock.cache[ovnCmd.table]; !ok {
				errors = append(errors,
					fmt.Errorf("command to delete entry from %s when cache doesn't exist", ovnCmd.table))
				continue
			}
			if err := mock.updateCache(ovnCmd.table, ovnCmd.objName, ovnCmd.objUpdate, cache); err != nil {
				errors = append(errors, err)
			}
		default:
			errors = append(errors,
				fmt.Errorf("invalid command op: %s", ovnCmd.op))
		}

	}
	return aggErrors.NewAggregate(errors)
}

// updateCache takes an object by name objName and updates it's fields specified as
// update in the mock ovn client's db cache
// It also allows faking errors in command execution during updates
func (mock *MockOVNClient) updateCache(table string, objName string, update UpdateCache, mockCache MockObjectCacheByName) error {
	// first check if an error needs to be returned from a side-ways error cache lookup
	cachedErr := mock.retFromErrorCache(table, objName, update.FieldType)
	if cachedErr != nil {
		return cachedErr
	}
	switch table {
	case LogicalSwitchPortType:
		return mock.updateLSPCache(objName, update, mockCache)
	default:
		return fmt.Errorf("mock cache updates for %s are not implemented yet", table)
	}
}

// insert a fake error to the cache
func (mock *MockOVNClient) AddToErrorCache(table, name, fieldType string, err error) {
	mock.errorCache[fmt.Sprintf("%s:%s:%s", table, name, fieldType)] = err
}

// get fake error from cache
func (mock *MockOVNClient) retFromErrorCache(table, name, fieldType string) error {
	key := fmt.Sprintf("%s:%s:%s", table, name, fieldType)
	if val, ok := mock.errorCache[key]; ok {
		return val
	}
	return nil
}

// delete an instance of fake error from cache
func (mock *MockOVNClient) RemoveFromErrorCache(table, name, fieldType string) {
	key := fmt.Sprintf("%s:%s:%s", table, name, fieldType)
	delete(mock.errorCache, key)
}

func (cmd *MockOVNCommand) Execute() error {
	return cmd.Exe.Execute(cmd)
}
