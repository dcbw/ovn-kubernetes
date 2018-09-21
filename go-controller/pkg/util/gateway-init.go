package util

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"net"
	"strings"
)

const (
	onhostGatewayIP = "169.254.33.1"
	onhostGatewayCIDR = onhostGatewayIP+"/24"
	onhostGatewayIP2  = "169.254.33.2"
)


// GetK8sClusterRouter returns back the OVN distibuted router
func GetK8sClusterRouter() (string, error) {
	k8sClusterRouter, stderr, err := RunOVNNbctl("--data=bare",
		"--no-heading", "--columns=_uuid", "find", "logical_router",
		"external_ids:k8s-cluster-router=yes")
	if err != nil {
		logrus.Errorf("Failed to get k8s cluster router, stderr: %q, "+
			"error: %v", stderr, err)
		return "", err
	}
	if k8sClusterRouter == "" {
		return "", fmt.Errorf("Failed to get k8s cluster router")
	}

	return k8sClusterRouter, nil
}

func getLocalSystemID() (string, error) {
	localSystemID, stderr, err := RunOVSVsctl("--if-exists", "get",
		"Open_vSwitch", ".", "external_ids:system-id")
	if err != nil {
		logrus.Errorf("No system-id configured in the local host, "+
			"stderr: %q, error: %v", stderr, err)
		return "", err
	}
	if localSystemID == "" {
		return "", fmt.Errorf("No system-id configured in the local host")
	}

	return localSystemID, nil
}

func lockNBForGateways() error {
	localSystemID, err := getLocalSystemID()
	if err != nil {
		return err
	}

	stdout, stderr, err := RunOVNNbctlWithTimeout(60, "--", "wait-until",
		"nb_global", ".", "external-ids:gateway-lock=\"\"", "--", "set",
		"nb_global", ".", "external_ids:gateway-lock="+localSystemID)
	if err != nil {
		return fmt.Errorf("Failed to set gateway-lock "+
			"stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
	}
	return nil
}

func unlockNBForGateways() {
	stdout, stderr, err := RunOVNNbctl("--", "set", "nb_global", ".",
		"external-ids:gateway-lock=\"\"")
	if err != nil {
		logrus.Errorf("Failed to delete lock for gateways, "+
			"stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
	}
}

func generateGatewayIP() (string, error) {
	// All the routers connected to "join" switch are in 100.64.1.0/24
	// network and they have their external_ids:connect_to_join set.
	stdout, stderr, err := RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=network", "find", "logical_router_port",
		"external_ids:connect_to_join=yes")
	if err != nil {
		logrus.Errorf("Failed to get logical router ports which connect to "+
			"\"join\" switch, stdout: %q, stderr: %q, error: %v",
			stdout, stderr, err)
		return "", err
	}
	ips := strings.Split(strings.TrimSpace(stdout), "\n")

	ipStart, ipStartNet, _ := net.ParseCIDR("100.64.1.0/24")
	ipMax, _, _ := net.ParseCIDR("100.64.1.255/24")
	n, _ := ipStartNet.Mask.Size()
	for !ipStart.Equal(ipMax) {
		ipStart = NextIP(ipStart)
		if ipStart.Equal(ipMax) {
			break
		}
		used := false
		for _, v := range ips {
			ipCompare, _, _ := net.ParseCIDR(v)
			if ipStart.String() == ipCompare.String() {
				used = true
				break
			}
		}
		if !used {
			return fmt.Sprintf("%s/%d", ipStart.String(), n), nil
		}
		// Jump over gateway second address
		ipStart = NextIP(ipStart)
	}
	return "", fmt.Errorf("ran out of gateway IPs")
}

func getMacForIp(iface, ip string) (string, error) {
	stdout, stderr, err := RunIP("neigh", "show", "dev", iface, "to", ip)
	if err != nil {
		return "", fmt.Errorf("failed to read %q ARP table entries, stderr:%s (%v)", iface, stderr, err)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 1 {
		return "", fmt.Errorf("got empty ARP table output")
	}
	items := strings.Split(lines[0], " ")
	if len(items) < 3 {
		return "", fmt.Errorf("failed to parse ARP entry output %q", lines[0])
	}
	if _, err := net.ParseMAC(items[2]); err != nil {
		return "", fmt.Errorf("failed to read default gateway ARP table entry, stderr:%s (%v)", stderr, err)
	}
	return items[2], nil
}

func getIpAsHex(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("failed to parse IP %q", ipStr)
	}
	if ip.To4() != nil {
		ip = ip.To4()
	}
	asHex := ""
	for i := 0; i < len(ip); i++ {
		asHex += fmt.Sprintf("%02x", ip[i])
	}
	return asHex, nil
}

// GatewayInit creates a gateway router for the local chassis.
func GatewayInit(clusterIPSubnet, nodeName, physicalIntf, physicalCIDR, physicalMacAddress,
	defaultGW, rampoutIPSubnet string,
	gatewayLBEnable bool) error {

	physicalIP, _, _ := net.ParseCIDR(physicalCIDR)

	k8sClusterRouter, err := GetK8sClusterRouter()
	if err != nil {
		return err
	}

	systemID, err := getLocalSystemID()
	if err != nil {
		return err
	}

	// Create a gateway router.
	gatewayRouter := "GR_" + nodeName
	stdout, stderr, err := RunOVNNbctl("--", "--may-exist", "lr-add",
		gatewayRouter, "--", "set", "logical_router", gatewayRouter,
		"options:chassis="+systemID)
	if err != nil {
		logrus.Errorf("Failed to create logical router %v, stdout: %q, "+
			"stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
		return err
	}

	// Connect gateway router to switch "join".
	routerMac, stderr, err := RunOVNNbctl("--if-exist", "get",
		"logical_router_port", "rtoj-"+gatewayRouter, "mac")
	if err != nil {
		logrus.Errorf("Failed to get logical router port, stderr: %q, "+
			"error: %v", stderr, err)
		return err
	}

	var routerIP string
	if routerMac == "" {
		routerMac = GenerateMac()
		if err = func() error {
			err = lockNBForGateways()
			if err != nil {
				return err
			}
			defer unlockNBForGateways()
			routerIP, err = generateGatewayIP()
			if err != nil {
				return err
			}

			stdout, stderr, err = RunOVNNbctl("--", "--may-exist", "lrp-add",
				gatewayRouter, "rtoj-"+gatewayRouter, routerMac, routerIP,
				"--", "set", "logical_router_port", "rtoj-"+gatewayRouter,
				"external_ids:connect_to_join=yes")
			if err != nil {
				return fmt.Errorf("failed to add logical port to router, stdout: %q, "+
					"stderr: %q, error: %v", stdout, stderr, err)
			}
			return nil
		}(); err != nil {
			logrus.Errorf(err.Error())
			return err
		}
	}

	if routerIP == "" {
		stdout, stderr, err = RunOVNNbctl("--if-exists", "get",
			"logical_router_port", "rtoj-"+gatewayRouter, "networks")
		if err != nil {
			logrus.Errorf("failed to get routerIP for %s "+
				"stdout: %q, stderr: %q, error: %v",
				"rtoj-"+gatewayRouter, stdout, stderr, err)
			return err
		}
		routerIP = strings.Trim(stdout, "[]\"")
	}

	// Tag the gateway router with its externalIP
	rip, rnet, err := net.ParseCIDR(routerIP)
	rnet.IP = rip
	lrCIDR := net.IPNet{IP: NextIP(rip), Mask:rnet.Mask}
	stdout, stderr, err = RunOVNNbctl("set", "logical_router", gatewayRouter,
		"external_ids:external_ip="+lrCIDR.String())
	if err != nil {
		logrus.Errorf("Failed to create logical router %v, stdout: %q, "+
			"stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
		return err
	}

	// Connect the switch "join" to the router.
	stdout, stderr, err = RunOVNNbctl("--", "--may-exist", "lsp-add",
		"join", "jtor-"+gatewayRouter, "--", "set", "logical_switch_port",
		"jtor-"+gatewayRouter, "type=router",
		"options:router-port=rtoj-"+gatewayRouter,
		"addresses="+"\""+routerMac+"\"")
	if err != nil {
		logrus.Errorf("Failed to add logical port to switch, stdout: %q, "+
			"stderr: %q, error: %v", stdout, stderr, err)
		return err
	}

	// Add a static route in GR with distributed router as the nexthop.
	stdout, stderr, err = RunOVNNbctl("--may-exist", "lr-route-add",
		gatewayRouter, clusterIPSubnet, "100.64.1.1", "rtoj-"+gatewayRouter)
	if err != nil {
		logrus.Errorf("Failed to add a static route in GR with distributed "+
			"router as the nexthop, stdout: %q, stderr: %q, error: %v",
			stdout, stderr, err)
		return err
	}

	// Add a default route in distributed router with first GR as the nexthop.
	stdout, stderr, err = RunOVNNbctl("--may-exist", "lr-route-add",
		k8sClusterRouter, "0.0.0.0/0", "100.64.1.2")
	if err != nil {
		logrus.Errorf("Failed to add a default route in distributed router "+
			"with first GR as the nexthop, stdout: %q, stderr: %q, error: %v",
			stdout, stderr, err)
		return err
	}

	if false {
		// Create 2 load-balancers for north-south traffic for each gateway
		// router.  One handles UDP and another handles TCP.
		var k8sNSLbTCP, k8sNSLbUDP string
		k8sNSLbTCP, stderr, err = RunOVNNbctl("--data=bare", "--no-heading",
			"--columns=_uuid", "find", "load_balancer",
			"external_ids:TCP_lb_gateway_router="+gatewayRouter)
		if err != nil {
			logrus.Errorf("Failed to get k8sNSLbTCP, stderr: %q, error: %v",
				stderr, err)
			return err
		}
		if k8sNSLbTCP == "" {
			k8sNSLbTCP, stderr, err = RunOVNNbctl("--", "create",
				"load_balancer",
				"external_ids:TCP_lb_gateway_router="+gatewayRouter)
			if err != nil {
				logrus.Errorf("Failed to create load balancer, stdout: %q, "+
					"stderr: %q, error: %v", stdout, stderr, err)
				return err
			}
		}

		k8sNSLbUDP, stderr, err = RunOVNNbctl("--data=bare", "--no-heading",
			"--columns=_uuid", "find", "load_balancer",
			"external_ids:UDP_lb_gateway_router="+gatewayRouter)
		if err != nil {
			logrus.Errorf("Failed to get k8sNSLbUDP, stderr: %q, error: %v",
				stderr, err)
			return err
		}
		if k8sNSLbUDP == "" {
			k8sNSLbUDP, stderr, err = RunOVNNbctl("--", "create",
				"load_balancer",
				"external_ids:UDP_lb_gateway_router="+gatewayRouter,
				"protocol=udp")
			if err != nil {
				logrus.Errorf("Failed to create load balancer, stdout: %q, "+
					"stderr: %q, error: %v", stdout, stderr, err)
				return err
			}
		}

		// Add north-south load-balancers to the gateway router.
		stdout, stderr, err = RunOVNNbctl("set", "logical_router",
			gatewayRouter, "load_balancer="+k8sNSLbTCP)
		if err != nil {
			logrus.Errorf("Failed to set north-south load-balancers to the "+
				"gateway router, stdout: %q, stderr: %q, error: %v",
				stdout, stderr, err)
			return err
		}
		stdout, stderr, err = RunOVNNbctl("add", "logical_router",
			gatewayRouter, "load_balancer", k8sNSLbUDP)
		if err != nil {
			logrus.Errorf("Failed to add north-south load-balancers to the "+
				"gateway router, stdout: %q, stderr: %q, error: %v",
				stdout, stderr, err)
			return err
		}
	}

	// Create the external switch for the physical interface to connect to.
	externalSwitch := "ext_" + nodeName
	stdout, stderr, err = RunOVNNbctl("--may-exist", "ls-add", externalSwitch)
	if err != nil {
		logrus.Errorf("Failed to create logical switch, stdout: %q, "+
			"stderr: %q, error: %v", stdout, stderr, err)
		return err
	}

	// Create a rampout OVS bridge.
	extBridgeName := "br-ext"
	_, stderr, err = RunOVSVsctl("--may-exist", "add-br", extBridgeName)
	if err != nil {
		return fmt.Errorf("Failed to create rampout bridge %s, "+
			"stderr:%s (%v)", extBridgeName, stderr, err)
	}
	_, stderr, err = RunIP("link", "set", extBridgeName, "up")
	if err != nil {
		return fmt.Errorf("failed to up %s, stderr:%s (%v)", extBridgeName, stderr, err)
	}

	offhostIntf := "offhost"
	_, stderr, err = RunOVSVsctl("--may-exist", "add-port",
		extBridgeName, offhostIntf, "--", "set", "Interface", offhostIntf,
		"ofport_request=2", "type=internal")
	if err != nil {
		return fmt.Errorf("Failed to create rampout bridge %s offhost "+
			"interface %s, stderr:%s (%v)", extBridgeName, offhostIntf,
			stderr, err)
	}
	_, stderr, err = RunIP("link", "set", offhostIntf, "up")
	if err != nil {
		return fmt.Errorf("failed to up %s, stderr:%s (%v)", offhostIntf, stderr, err)
	}

	onhostIntf := "onhost"
	_, stderr, err = RunOVSVsctl("--may-exist", "add-port",
		extBridgeName, onhostIntf, "--", "set", "Interface", onhostIntf,
		"ofport_request=3", "type=internal")
	if err != nil {
		return fmt.Errorf("Failed to create rampout bridge %s onhost "+
			"interface %s, stderr:%s (%v)", extBridgeName, onhostIntf,
			stderr, err)
	}
	_, stderr, err = RunIP("link", "set", onhostIntf, "up")
	if err != nil {
		return fmt.Errorf("failed to up %s, stderr:%s (%v)", offhostIntf, stderr, err)
	}
	_, stderr, err = RunIP("addr", "add", "dev", onhostIntf, onhostGatewayCIDR)
	if err != nil  && !strings.Contains(stderr, "File exists") {
		return fmt.Errorf("failed to set address on %s, stderr:%s (%v)", onhostIntf, stderr, err)
	}
	intf, err := net.InterfaceByName(onhostIntf)
	if err != nil {
		return err
	}
	onhostMac := intf.HardwareAddr.String()
	_, stderr, err = RunIP("neigh", "replace", onhostGatewayIP2, "lladdr", onhostMac, "dev", onhostIntf)
	if err != nil {
		return fmt.Errorf("failed to set onhost static ARP, stderr:%s (%v)", stderr, err)
	}

	// Link rampout bridge and OVN bridge
	rampExt := "ext"
	rampInt := "int"

	_, stderr, err = RunIP("link", "add", "dev", rampInt, "type", "veth", "peer", "name", rampExt)
	if err != nil {
		return fmt.Errorf("failed to add int/ext, stderr:%s (%v)", stderr, err)
	}
	_, stderr, err = RunIP("link", "set", rampInt, "up")
	if err != nil {
		return fmt.Errorf("failed to up %s, stderr:%s (%v)", rampInt, stderr, err)
	}
	_, stderr, err = RunIP("link", "set", rampExt, "up")
	if err != nil {
		return fmt.Errorf("failed to up %s, stderr:%s (%v)", rampExt, stderr, err)
	}

	extIfaceID := rampExt + "_" + nodeName
	_, stderr, err = RunOVSVsctl("--may-exist",
	        "add-port", "br-int", rampInt, "--", 
		"add-port", extBridgeName, rampExt, "--",
		"set", "Interface", rampInt, "external-ids:iface-id="+extIfaceID)
	if err != nil {
		return fmt.Errorf("Failed to create rampout patch ports %s/%s"+
			", stderr:%s (%v)", rampExt, rampInt, stderr, err)
	}

if false {
	_, stderr, err = RunOVSVsctl("--may-exist",
	        "add-port", "br-int", rampInt, "--", 
		"add-port", extBridgeName, rampExt, "--",
		"set", "Interface", rampInt, "type=patch", "options:peer="+rampExt, "external-ids:iface-id="+extIfaceID, "--",
		"set", "Interface", rampExt, "type=patch", "options:peer="+rampInt, "ofport_request=11")
	if err != nil {
		return fmt.Errorf("Failed to create rampout patch ports %s/%s"+
			", stderr:%s (%v)", rampExt, rampInt, stderr, err)
	}
}

	// Add external interface as a logical port to external_switch.
	// This is a learning switch port with "unknown" address. The external
	// world is accessed via this port.
	stdout, stderr, err = RunOVNNbctl("--", "--may-exist", "lsp-add",
		externalSwitch, extIfaceID, "--", "lsp-set-addresses", extIfaceID, "unknown")
	if err != nil {
		logrus.Errorf("Failed to add logical port to switch, stdout: %q, "+
			"stderr: %q, error: %v", stdout, stderr, err)
		return err
	}

	lrMac := GenerateMac()

	// Connect GR to external_switch with mac address of external interface
	// and that IP address.
	stdout, stderr, err = RunOVNNbctl("--", "--may-exist", "lrp-add",
		gatewayRouter, "rtoe-"+gatewayRouter, lrMac, lrCIDR.String(),
		"--", "set", "logical_router_port", "rtoe-"+gatewayRouter,
		"external-ids:gateway-physical-ip=yes")
	if err != nil {
		logrus.Errorf("Failed to add logical port to router, stdout: %q, "+
			"stderr: %q, error: %v", stdout, stderr, err)
		return err
	}

	// Connect the external_switch to the router.
	stdout, stderr, err = RunOVNNbctl("--", "--may-exist", "lsp-add",
		externalSwitch, "etor-"+gatewayRouter, "--", "set",
		"logical_switch_port", "etor-"+gatewayRouter, "type=router",
		"options:router-port=rtoe-"+gatewayRouter,
		"addresses="+"\""+lrMac+"\"")
	if err != nil {
		logrus.Errorf("Failed to add logical port to router, stdout: %q, "+
			"stderr: %q, error: %v", stdout, stderr, err)
		return err
	}

	// Add a static route in GR with physical gateway as the default next hop.
	if defaultGW != "" {
		stdout, stderr, err = RunOVNNbctl("--may-exist", "lr-route-add",
			gatewayRouter, "0.0.0.0/0", defaultGW,
			fmt.Sprintf("rtoe-%s", gatewayRouter))
		if err != nil {
			logrus.Errorf("Failed to add a static route in GR with physical "+
				"gateway as the default next hop, stdout: %q, "+
				"stderr: %q, error: %v", stdout, stderr, err)
			return err
		}
	}

	// When there are multiple gateway routers (which would be the likely
	// default for any sane deployment), we need to SNAT traffic
	// heading to the logical space with the Gateway router's IP so that
	// return traffic comes back to the same gateway router.
	if routerIP != "" {
		routerIPByte, _, err := net.ParseCIDR(routerIP)
		if err != nil {
			return err
		}
		stdout, stderr, err = RunOVNNbctl("set", "logical_router",
			gatewayRouter, "options:lb_force_snat_ip="+routerIPByte.String())
		if err != nil {
			logrus.Errorf("Failed to set logical router, stdout: %q, "+
				"stderr: %q, error: %v", stdout, stderr, err)
			return err
		}
		if rampoutIPSubnet != "" {
			rampoutIPSubnets := strings.Split(rampoutIPSubnet, ",")
			for _, rampoutIPSubnet = range rampoutIPSubnets {
				_, _, err = net.ParseCIDR(rampoutIPSubnet)
				if err != nil {
					continue
				}

				// Add source IP address based routes in distributed router
				// for this gateway router.
				stdout, stderr, err = RunOVNNbctl("--may-exist",
					"--policy=src-ip", "lr-route-add", k8sClusterRouter,
					rampoutIPSubnet, routerIPByte.String())
				if err != nil {
					logrus.Errorf("Failed to add source IP address based "+
						"routes in distributed router, stdout: %q, "+
						"stderr: %q, error: %v", stdout, stderr, err)
					return err
				}
			}
		}
	}

	// Get MAC address of default gateway
	defaultGWMac, err := getMacForIp(physicalIntf, defaultGW)
	if err != nil {
		return err
	}
	defaultGWMacRaw := strings.Replace(defaultGWMac, ":", "", -1)

	// Handle ARP for gateway address internally
	defaultGWRaw, err := getIpAsHex(defaultGW)
	if err != nil {
		return err
	}
	_, stderr, err = RunOVSOfctl("-O", "openflow13", "add-flow", extBridgeName,
		"table=0, priority=100, in_port="+rampExt+", arp, arp_tpa="+defaultGW+", actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],mod_dl_src:"+defaultGWMac+",load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],load:0x"+defaultGWMacRaw+"->NXM_NX_ARP_SHA[],load:0x"+defaultGWRaw+"->NXM_OF_ARP_SPA[],IN_PORT")
	if err != nil {
		return fmt.Errorf("failed to set up rampout bridge ARP flow,"+
			"stderr: %q, error: %v", stderr, err)
	}

	// External -> Pod
	_, stderr, err = RunOVSOfctl("-O", "openflow13", "add-flow", extBridgeName,
		"table=0, priority=50, in_port="+offhostIntf+", ip, actions=ct(nat,table=20)")
	if err != nil {
		return fmt.Errorf("failed to set up rampout bridge flows,"+
			"stderr: %q, error: %v", stderr, err)
	}
	_, stderr, err = RunOVSOfctl("-O", "openflow13", "add-flow", extBridgeName,
		"table=0, priority=50, in_port="+onhostIntf+", ip, actions=ct(nat,table=20)")
	if err != nil {
		return fmt.Errorf("failed to set up rampout bridge flows,"+
			"stderr: %q, error: %v", stderr, err)
	}

	// Pod -> host; NAT packet to onhost gateway IP and send it out
	onhostMacRaw := strings.Replace(onhostMac, ":", "", -1)
	_, stderr, err = RunOVSOfctl("-O", "openflow13", "add-flow", extBridgeName,
		"table=0, priority=25, in_port="+rampExt+", ip, nw_dst="+physicalIP.String()+", actions=load:0x"+onhostMacRaw+"->NXM_OF_ETH_DST[],goto_table:10")
	if err != nil {
		return fmt.Errorf("failed to set up rampout bridge flows,"+
			"stderr: %q, error: %v", stderr, err)
	}
	_, stderr, err = RunOVSOfctl("-O", "openflow13", "add-flow", extBridgeName,
		"table=10, in_port="+rampExt+", ip, actions=ct(commit,nat(src="+onhostGatewayIP2+"),exec(load:0x6->NXM_NX_CT_MARK[])),output:"+onhostIntf)
	if err != nil {
		return fmt.Errorf("failed to set up rampout bridge flows,"+
			"stderr: %q, error: %v", stderr, err)
	}

	// Pod -> external; rewrite MAC to NIC's and NAT packet out
	physicalMacRaw := strings.Replace(physicalMacAddress, ":", "", -1)
	_, stderr, err = RunOVSOfctl("-O", "openflow13", "add-flow", extBridgeName,
		"table=0, priority=10, in_port="+rampExt+", ip, actions=load:0x"+physicalMacRaw+"->NXM_OF_ETH_SRC[],goto_table:20")
	if err != nil {
		return fmt.Errorf("failed to set up rampout bridge flows,"+
			"stderr: %q, error: %v", stderr, err)
	}
	_, stderr, err = RunOVSOfctl("-O", "openflow13", "add-flow", extBridgeName,
		"table=20, in_port="+rampExt+", ip, actions=ct(commit,nat(src="+physicalIP.String()+"),exec(load:0x5->NXM_NX_CT_MARK[])),output:"+offhostIntf)
	if err != nil {
		return fmt.Errorf("failed to set up rampout bridge flows,"+
			"stderr: %q, error: %v", stderr, err)
	}

	// established and related connections go to OVN
	lrMacRaw := strings.Replace(lrMac, ":", "", -1)
	_, stderr, err = RunOVSOfctl("-O", "openflow13", "add-flow", extBridgeName,
		"table=20, priority=100, ct_state=+trk+est, actions=load:0x"+lrMacRaw+"->NXM_OF_ETH_DST[],output:"+rampExt)
	if err != nil {
		return fmt.Errorf("failed to set up rampout bridge flows,"+
			"stderr: %q, error: %v", stderr, err)
	}
	_, stderr, err = RunOVSOfctl("-O", "openflow13", "add-flow", extBridgeName,
		"table=20, priority=100, ct_state=+trk+rel, actions=load:0x"+lrMacRaw+"->NXM_OF_ETH_DST[],output:"+rampExt)
	if err != nil {
		return fmt.Errorf("failed to set up rampout bridge flows,"+
			"stderr: %q, error: %v", stderr, err)
	}

	_, stderr, err = RawExec("tc", "qdisc", "add", "dev", physicalIntf, "ingress")
	if err != nil {
		return fmt.Errorf("failed to set tc qdisc on %s, stderr:%s %v", physicalIntf, stderr, err)
	}
	_, stderr, err = RawExec("tc", "filter", "add", "dev", physicalIntf, "handle", "776", "ingress", "protocol", "ip", "prio", "1", "flower", "indev", physicalIntf, "action", "connmark", "continue")
	if err != nil {
		return fmt.Errorf("failed to set tc qdisc on %s, stderr:%s %v", physicalIntf, stderr, err)
	}
	_, stderr, err = RawExec("tc", "filter", "add", "dev", physicalIntf, "handle", "5", "ingress", "protocol", "ip", "prio", "2", "fw", "indev", physicalIntf, "action", "mirred", "egress", "redirect", "dev", offhostIntf)
	if err != nil {
		return fmt.Errorf("failed to set tc qdisc on %s, stderr:%s %v", physicalIntf, stderr, err)
	}

	// OVN -> offhost
	_, stderr, err = RawExec("tc", "qdisc", "add", "dev", offhostIntf, "ingress")
	if err != nil {
		return fmt.Errorf("failed to set tc qdisc on %s, stderr:%s (%v)", offhostIntf, stderr, err)
	}
	_, stderr, err = RawExec("tc", "filter", "add", "dev", offhostIntf, "handle", "778", "ingress", "protocol", "ip", "prio", "1", "flower", "indev", offhostIntf, "action", "mirred", "egress", "redirect", "dev", physicalIntf)
	if err != nil {
		return fmt.Errorf("failed to set tc qdisc on %s, stderr:%s (%v)", offhostIntf, stderr, err)
	}

	return nil
}
