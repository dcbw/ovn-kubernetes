package testing

import (
	"fmt"
	"runtime"
	"syscall"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/ovnbindings"
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
	Execute(cmds ...ovnbindings.OVNCommandInterface) error
}

// mock ovn client for testing
type MockOVNClient struct {
	db string
	// cache holds ovn db rows by table name as the key
	cache map[string]MockObjectCacheByName
	// error injection
	// keys are of the form: Table:Name:FieldType
	errorCache map[string]error
	// represents connected client
	connected bool
}

var _ ovnbindings.OVNInterface = &MockOVNClient{}

type MockOVNCommand struct {
	Exe       MockExecution
	op        string
	table     string
	objName   string
	obj       interface{}
	objUpdate UpdateCache
}

// MockOVNCommand implements OVNCommandInterface
var _ ovnbindings.OVNCommandInterface = &MockOVNCommand{}

// return a new mock client to operate on db
func NewMockOVNClient(db string) *MockOVNClient {
	return &MockOVNClient{
		db:         db,
		cache:      make(map[string]MockObjectCacheByName),
		errorCache: make(map[string]error),
		connected:  true,
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

// Close connection to OVN
func (mock *MockOVNClient) Close() error {
	mock.connected = false
	return nil
}

// Exec command, support multiple commands in one transaction.
// executes commands ensuring their temporal consistency
func (mock *MockOVNClient) Execute(cmds ...ovnbindings.OVNCommandInterface) error {
	if !mock.connected {
		return syscall.ENOTCONN
	}

	errors := make([]error, 0, len(cmds))
	for _, cmd := range cmds {
		// go over each mock command and apply the
		// individual command's operations to the
		// cache
		ovnCmd, ok := cmd.(*MockOVNCommand)
		if !ok {
			klog.Errorf("Type assertion failed for mock command")
			panic("type assertion failed for mock command")
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
