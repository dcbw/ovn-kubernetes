package ovn

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/urfave/cli"
	fakeexec "k8s.io/utils/exec/testing"

	"github.com/openvswitch/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/openvswitch/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/openvswitch/ovn-kubernetes/go-controller/pkg/util"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var tmpDir string

var _ = AfterSuite(func() {
	err := os.RemoveAll(tmpDir)
	Expect(err).NotTo(HaveOccurred())
})

func createTempFile(name string) (string, error) {
	fname := filepath.Join(tmpDir, name)
	if err := ioutil.WriteFile(fname, []byte{0x20}, 0644); err != nil {
		return "", err
	}
	return fname, nil
}

var _ = Describe("Management Port Operations", func() {
	var tmpErr error
	var app *cli.App

	tmpDir, tmpErr = ioutil.TempDir("", "clusternodetest_certdir")
	if tmpErr != nil {
		GinkgoT().Errorf("failed to create tempdir: %v", tmpErr)
	}

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.RestoreDefaultConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags
	})

	It("sets up the management port", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName          string = "node1"
				lrpMAC            string = "00:00:00:05:46:C3"
				clusterRouterUUID string = "5cedba03-679f-41f3-b00e-b8ed7437bc6c"
				nodeSubnet        string = "10.1.1.0/24"
				mgtPortMAC        string = "00:00:00:55:66:77"
				mgtPort           string = "k8s-"+nodeName
				mgtPortIP         string = "10.1.1.2"
				mgtPortCIDR       string = mgtPortIP+"/24"
				clusterCIDR       string = "10.1.0.0/16"
				serviceCIDR       string = "172.16.0.0/16"
			)

			fakeCmds := ovntest.AddFakeCmd(nil, &ovntest.ExpectedCmd{
				Cmd: "ovn-nbctl --timeout=5 --if-exist get logical_router_port rtos-"+nodeName+" mac",
				// Return a known MAC; otherwise code autogenerates it
				Output: lrpMAC,
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=5 --data=bare --no-heading --columns=_uuid find logical_router external_ids:k8s-cluster-router=yes",
				Output: clusterRouterUUID,
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=5 --may-exist lrp-add "+clusterRouterUUID+" rtos-"+nodeName+" "+lrpMAC+" 10.1.1.1/24",
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=5 -- --may-exist ls-add "+nodeName+" -- set logical_switch "+nodeName+" other-config:subnet="+nodeSubnet+" external-ids:gateway_ip=10.1.1.1/24",
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=5 -- --may-exist lsp-add "+nodeName+" stor-"+nodeName+" -- set logical_switch_port stor-"+nodeName+" type=router options:router-port=rtos-"+nodeName+" addresses=\""+lrpMAC+"\"",
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ovs-vsctl --timeout=5 -- --may-exist add-br br-int",
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ovs-vsctl --timeout=5 -- --may-exist add-port br-int "+mgtPort+" -- set interface "+mgtPort+" type=internal mtu_request=1400 external-ids:iface-id="+mgtPort,
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ovs-vsctl --timeout=5 --if-exists get interface "+mgtPort+" mac_in_use",
				Output: mgtPortMAC,
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=5 -- --may-exist lsp-add "+nodeName+" "+mgtPort+" -- lsp-set-addresses "+mgtPort+" "+mgtPortMAC+" "+mgtPortIP,
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ip link set "+mgtPort+" up",
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ip addr flush dev "+mgtPort,
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ip addr add "+mgtPortCIDR+" dev "+mgtPort,
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ip route flush "+clusterCIDR,
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ip route add "+clusterCIDR+" via 10.1.1.1",
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ip route flush "+serviceCIDR,
			})
			fakeCmds = ovntest.AddFakeCmd(fakeCmds, &ovntest.ExpectedCmd{
				Cmd:    "ip route add "+serviceCIDR+" via 10.1.1.1",
			})

			fexec := &fakeexec.FakeExec{
				CommandScript: fakeCmds,
				LookPathFunc: func(file string) (string, error) {
					return fmt.Sprintf("/fake-bin/%s", file), nil
				},
			}

			err := util.SetExec(fexec)
			Expect(err).NotTo(HaveOccurred())

			_, err = config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			err = CreateManagementPort(nodeName, nodeSubnet, clusterCIDR, serviceCIDR)
			Expect(err).NotTo(HaveOccurred())

			Expect(fexec.CommandCalls).To(Equal(len(fakeCmds)))
			return nil
		}

		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())
	})
})
