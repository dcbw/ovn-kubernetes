package controller

import (
	"bytes"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"

	"github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	houtil "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"github.com/openshift/origin/pkg/util/netutils"
	kapi "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// MasterController is the master hybrid overlay controller
type MasterController struct {
	kube      *kube.Kube
	allocator []*netutils.SubnetAllocator
}

// NewMaster a new master controller that listens for node events
func NewMaster(clientset kubernetes.Interface, subnets []config.CIDRNetworkEntry) (*MasterController, error) {
	m := &MasterController{
		kube: &kube.Kube{KClient: clientset},
	}

	alreadyAllocated := make([]string, 0)
	existingNodes, err := m.kube.GetNodes()
	if err != nil {
		return nil, fmt.Errorf("Error in initializing/fetching subnets: %v", err)
	}
	for _, node := range existingNodes.Items {
		if houtil.IsWindowsNode(&node) {
			hostsubnet, ok := node.Annotations[types.HybridOverlayHostSubnet]
			if ok {
				alreadyAllocated = append(alreadyAllocated, hostsubnet)
			}
		}
	}

	masterSubnetAllocatorList := make([]*netutils.SubnetAllocator, 0)
	// NewSubnetAllocator is a subnet IPAM, which takes a CIDR (first argument)
	// and gives out subnets of length 'hostSubnetLength' (second argument)
	// but omitting any that exist in 'subrange' (third argument)
	for _, subnet := range subnets {
		subrange := make([]string, 0)
		for _, allocatedRange := range alreadyAllocated {
			firstAddress, _, err := net.ParseCIDR(allocatedRange)
			if err != nil {
				logrus.Errorf("error parsing already allocated hostsubnet %q: %v", allocatedRange, err)
				continue
			}
			if subnet.CIDR.Contains(firstAddress) {
				subrange = append(subrange, allocatedRange)
			}
		}
		subnetAllocator, err := netutils.NewSubnetAllocator(subnet.CIDR.String(), 32-subnet.HostSubnetLength, subrange)
		if err != nil {
			return nil, fmt.Errorf("error creating subnet allocator for %q: %v", subnet.CIDR.String(), err)
		}
		masterSubnetAllocatorList = append(masterSubnetAllocatorList, subnetAllocator)
	}
	m.allocator = masterSubnetAllocatorList

	return m, nil
}

// Start is the top level function to run hybrid overlay in master mode
func (m *MasterController) Start(wf *factory.WatchFactory, stopChan chan struct{}) error {
	return houtil.StartNodeWatch(m, wf, stopChan)
}

func parseNodeHostSubnet(node *kapi.Node, annotation string) (*net.IPNet, error) {
	sub, ok := node.Annotations[annotation]
	if !ok {
		return nil, nil
	}

	_, subnet, err := net.ParseCIDR(sub)
	if err != nil {
		return nil, fmt.Errorf("error parsing node %s annotation %s value %q: %v",
			node.Name, annotation, sub, err)
	}

	return subnet, nil
}

func parseNodeDRMAC(node *kapi.Node) (net.HardwareAddr, error) {
	drmac, ok := node.Annotations[types.HybridOverlayDrMac]
	if !ok {
		return nil, nil
	}

	hwaddr, err := net.ParseMAC(drmac)
	if err != nil {
		return nil, fmt.Errorf("error parsing node %s annotation %s value %q: %v",
			node.Name, types.HybridOverlayDrMac, drmac, err)
	}

	return hwaddr, nil
}

func sameCIDR(a, b *net.IPNet) bool {
	if a == b {
		return true
	} else if (a == nil && b != nil) || (a != nil && b == nil) {
		return false
	}
	return a.IP.Equal(b.IP) && bytes.Equal(a.Mask, b.Mask)
}

func (m *MasterController) updateNodeAnnotation(node *kapi.Node) {
	extHostsubnet, _ := parseNodeHostSubnet(node, types.HybridOverlayHostSubnet)
	ovnHostsubnet, _ := parseNodeHostSubnet(node, ovn.OvnHostSubnet)

	var err error
	if !houtil.IsWindowsNode(node) {
		if ovnHostsubnet == nil {
			if extHostsubnet != nil {
				// remove any HybridOverlayHostSubnet
				logrus.Infof("Removed node %s hybrid overlay HostSubnet", node.Name)
				err = m.kube.DeleteAnnotationOnNode(node, types.HybridOverlayHostSubnet)
			}
		} else if !sameCIDR(ovnHostsubnet, extHostsubnet) {
			// sync the HybridHostSubnet with the OVN-assigned one
			logrus.Infof("Sycned node %s hybrid overlay HostSubnet %s", node.Name, ovnHostsubnet.String())
			err = m.kube.SetAnnotationOnNode(node, types.HybridOverlayHostSubnet, ovnHostsubnet.String())
		}
		if err != nil {
			logrus.Errorf("Failed to sync node %s hybrid overlay HostSubnet: %v", node.Name, err)
		}
		return
	}

	// Do not create a subnet if the node already has a subnet
	if extHostsubnet != nil {
		return
	}

	// Node doesn't have a subnet assigned; reserve a new one for it
	var subnetAllocator *netutils.SubnetAllocator
	err = netutils.ErrSubnetAllocatorFull
	for _, subnetAllocator = range m.allocator {
		extHostsubnet, err = subnetAllocator.GetNetwork()
		if err == netutils.ErrSubnetAllocatorFull {
			// Current subnet exhausted, check next possible subnet
			continue
		} else if err != nil {
			logrus.Errorf("Error allocating network for node %s: %v", node.Name, err)
			return
		}
		logrus.Infof("Allocated node %s hybrid overlay HostSubnet %s", node.Name, extHostsubnet.String())
		break
	}
	if err == netutils.ErrSubnetAllocatorFull {
		logrus.Errorf("Error allocating network for node %s: %v", node.Name, err)
		return
	}

	defer func() {
		if err != nil {
			_ = subnetAllocator.ReleaseNetwork(extHostsubnet)
		}
	}()

	// Set the HostSubnet annotation on the node object to signal
	// to nodes that their logical infrastructure is set up and they can
	// proceed with their initialization
	err = m.kube.SetAnnotationOnNode(node, types.HybridOverlayHostSubnet, extHostsubnet.String())
	if err != nil {
		logrus.Errorf("Failed to set node %s hybrid overlay HostSubnet annotation %q: %v",
			node.Name, extHostsubnet.String(), err)
	} else {
		logrus.Infof("Set node %s hybrid overlay HostSubnet to %s", node.Name, extHostsubnet.String())
	}
}

func (m *MasterController) handleOverlayPort(node *kapi.Node) error {
	// Only applicable to Linux nodes
	if houtil.IsWindowsNode(node) {
		return nil
	}

	drMAC, err := parseNodeDRMAC(node)
	if drMAC == nil || err != nil {
		// No DRMAC; clean up
		m.deleteOverlayPort(node)
		return err
	}

	subnet, err := parseNodeHostSubnet(node, ovn.OvnHostSubnet)
	if subnet == nil || err != nil {
		// No subnet allocated yet; clean up
		m.deleteOverlayPort(node)
		return err
	}

	portName := houtil.GetHybridOverlayPortName(node.Name)
	portMAC, portIP, _ := util.GetPortAddresses(portName)
	if portMAC == nil || portIP == nil {
		if portMAC == nil {
			portMAC, _ = net.ParseMAC(util.GenerateMac())
		}
		if portIP == nil {
			// Get the 3rd address in the node's subnet; the first is taken
			// by the k8s-cluster-router port, the second by the management port
			first := util.NextIP(subnet.IP)
			second := util.NextIP(first)
			portIP = util.NextIP(second)
		}

		var stderr string
		_, stderr, err = util.RunOVNNbctl("--", "--may-exist", "lsp-add", node.Name, portName,
			"--", "lsp-set-addresses", portName, portMAC.String()+" "+portIP.String())
		if err != nil {
			return fmt.Errorf("failed to add hybrid overlay port for node %s"+
				", stderr:%s: %v", node.Name, stderr, err)
		}
	}

	return nil
}

func (m *MasterController) deleteOverlayPort(node *kapi.Node) {
	portName := houtil.GetHybridOverlayPortName(node.Name)
	_, _, _ = util.RunOVNNbctl("--", "--if-exists", "lsp-del", node.Name, portName)
}

// Add handles node additions
func (m *MasterController) Add(node *kapi.Node) {
	m.updateNodeAnnotation(node)

	if err := m.handleOverlayPort(node); err != nil {
		logrus.Warningf("failed to set up hybrid overlay logical switch port for %s: %v", node.Name, err)
	}
}

// Update handles node updates
func (m *MasterController) Update(oldNode, newNode *kapi.Node) {
	m.Add(newNode)
}

// Delete handles node deletions
func (m *MasterController) Delete(node *kapi.Node) {
	// Run delete for all nodes in case the OS annotation was lost or changed

	nodeSubnet, _ := parseNodeHostSubnet(node, types.HybridOverlayHostSubnet)
	if nodeSubnet == nil {
		return
	}

	var found bool
	for _, possibleSubnet := range m.allocator {
		if err := possibleSubnet.ReleaseNetwork(nodeSubnet); err == nil {
			logrus.Infof("Deleted HostSubnet %v for node %s", nodeSubnet, node.Name)
			found = true
			break
		}
	}
	if !found {
		// SubnetAllocator.network is an unexported field so the only way to figure out if a subnet is in a network is to try and delete it
		// if deletion succeeds then stop iterating, if the list is exhausted the node subnet wasn't deleteted return err
		logrus.Errorf("Error deleting subnet %v for node %q: subnet not found in any CIDR range or already available", nodeSubnet, node.Name)
	}

	m.deleteOverlayPort(node)
}

// Sync handles synchronizing the initial node list
func (m *MasterController) Sync(nodes []*kapi.Node) {
	// Unused because our initial node list sync needs to return
	// errors which this function cannot do
}
