package ovn

import (
	goovn "github.com/ebay/go-ovn"
	. "github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	mock "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/mock"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"github.com/urfave/cli/v2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	k8sTCPLoadBalancerIP  = "k8s_tcp_load_balancer"
	k8sUDPLoadBalancerIP  = "k8s_udp_load_balancer"
	k8sSCTPLoadBalancerIP = "k8s_sctp_load_balancer"
	fakeUUID              = mock.FakeUUID
)

type FakeOVN struct {
	fakeClient  *fake.Clientset
	watcher     *factory.WatchFactory
	controller  *Controller
	stopChan    chan struct{}
	fakeExec    *ovntest.FakeExec
	asf         *fakeAddressSetFactory
	ovnNBClient util.OVNInterface
	ovnSBClient util.OVNInterface
}

func NewFakeOVN(fexec *ovntest.FakeExec) *FakeOVN {
	err := util.SetExec(fexec)
	Expect(err).NotTo(HaveOccurred())
	return &FakeOVN{
		fakeExec: fexec,
		asf:      newFakeAddressSetFactory(),
	}
}

func (o *FakeOVN) start(ctx *cli.Context, objects ...runtime.Object) {
	_, err := config.InitConfig(ctx, o.fakeExec, nil)
	Expect(err).NotTo(HaveOccurred())

	o.fakeClient = fake.NewSimpleClientset(objects...)
	o.init()
}

func (o *FakeOVN) restart() {
	o.shutdown()
	o.init()
}

func (o *FakeOVN) shutdown() {
	close(o.stopChan)
	o.watcher.Shutdown()
	err := o.controller.ovnNBClient.Close()
	Expect(err).NotTo(HaveOccurred())
	err = o.controller.ovnSBClient.Close()
	Expect(err).NotTo(HaveOccurred())
}

func (o *FakeOVN) init() {
	var err error

	o.stopChan = make(chan struct{})
	o.watcher, err = factory.NewWatchFactory(o.fakeClient)
	Expect(err).NotTo(HaveOccurred())
	o.ovnNBClient = mock.NewMockOVNClient(goovn.DBNB)
	o.ovnSBClient = mock.NewMockOVNClient(goovn.DBSB)
	o.controller = NewOvnController(o.fakeClient, o.watcher,
		o.stopChan, o.asf, o.ovnNBClient,
		o.ovnSBClient)
	o.controller.multicastSupport = true

}

func mockAddNBDBError(table, name, field string, err error, ovnNBClient util.OVNInterface) {
	mockClient, ok := ovnNBClient.(*mock.MockOVNClient)
	if ok {
		mockClient.AddToErrorCache(table, name, field, err)
	}
}

func mockAddSBDBError(table, name, field string, err error, ovnSBClient util.OVNInterface) {
	mockClient, ok := ovnSBClient.(*mock.MockOVNClient)
	if ok {
		mockClient.AddToErrorCache(table, name, field, err)
	}
}

func mockDelNBDBError(table, name, field string, ovnNBClient util.OVNInterface) {
	mockClient, ok := ovnNBClient.(*mock.MockOVNClient)
	if ok {
		mockClient.RemoveFromErrorCache(table, name, field)
	}
}

func mockDelSBDBError(table, name, field string, ovnSBClient util.OVNInterface) {
	mockClient, ok := ovnSBClient.(*mock.MockOVNClient)
	if ok {
		mockClient.RemoveFromErrorCache(table, name, field)
	}
}
