// Copyright 2023 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package deviceplugin

import (
	"context"
	"net"
	"os"
	"path"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/oklog/run"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/klog/v2"
	"k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	devicePluginPath = "/tmp/"
	kubeletSocket    = devicePluginPath + "kubelet-test.sock"
	namespace        = "test.google.com"
	pluginSocketBase = namespace + "-testdevicetype.sock"
	resourceName     = namespace + "/testdevicetype"
)

//nolint:govet
type kubeletStub struct {
	sync.Mutex
	server         *grpc.Server
	socket         string
	pluginEndpoint string
}

// newKubeletStub returns an initialized kubeletStub for testing purpose.
func newKubeletStub(socket string) *kubeletStub {
	return &kubeletStub{
		socket: socket,
	}
}

// Minimal implementation of deviceplugin.RegistrationServer interface

func (k *kubeletStub) Register(_ context.Context, r *v1beta1.RegisterRequest) (*v1beta1.Empty, error) {
	k.Lock()
	defer k.Unlock()
	k.pluginEndpoint = r.Endpoint

	return &v1beta1.Empty{}, nil
}

func (k *kubeletStub) start() error {
	os.Remove(k.socket)

	s, err := net.Listen("unix", k.socket)
	if err != nil {
		return errors.Wrap(err, "Can't listen at the socket")
	}

	k.server = grpc.NewServer()

	v1beta1.RegisterRegistrationServer(k.server, k)

	go maybeLogError(func() error { return k.server.Serve(s) }, "unable to start server")

	// Wait till the grpcServer is ready to serve services.
	return waitForServer(k.socket, 10*time.Second)
}

type devicePluginStub struct{}

func (*devicePluginStub) GetDevicePluginOptions(context.Context, *v1beta1.Empty) (*v1beta1.DevicePluginOptions, error) {
	return &v1beta1.DevicePluginOptions{}, nil
}

func (*devicePluginStub) ListAndWatch(*v1beta1.Empty, v1beta1.DevicePlugin_ListAndWatchServer) error {
	return nil
}

func (*devicePluginStub) Allocate(_ context.Context, req *v1beta1.AllocateRequest) (*v1beta1.AllocateResponse, error) {
	res := &v1beta1.AllocateResponse{
		ContainerResponses: make([]*v1beta1.ContainerAllocateResponse, 0, len(req.ContainerRequests)),
	}
	return res, nil
}
func (*devicePluginStub) PreStartContainer(context.Context, *v1beta1.PreStartContainerRequest) (*v1beta1.PreStartContainerResponse, error) {
	return &v1beta1.PreStartContainerResponse{}, nil
}

func (*devicePluginStub) GetPreferredAllocation(context.Context, *v1beta1.PreferredAllocationRequest) (*v1beta1.PreferredAllocationResponse, error) {
	return &v1beta1.PreferredAllocationResponse{}, nil
}

// TestRegisterWithKublet does the followings:
// 1. starts a mock kubelet
// 2. starts a mock device plugin server
// 3. the mock device plugin successfully registers itself on the mock kubelet
// The mock device plugin server does not stop when no error. We use a timer to stop the mock
// device plugin server when no error. The mock device plugin server tries to restart
// for maxRestartTime before it claims error. So the timer waits for
// restartInterval*maxRestartTimes. We add a testBuffer to timer in case the timer ends before
// the mock device plugin server returns an error.
func TestRegisterWithKublet(t *testing.T) {
	// start a mock kubelet gRPC server
	kubelet := newKubeletStub(kubeletSocket)
	err := kubelet.start()
	if err != nil {
		t.Fatalf("%+v", err)
	}

	defer kubelet.server.Stop()

	// start a mock device plugin gRPC server, remove the socket if already exists
	socket := path.Join(devicePluginPath, pluginSocketBase)
	os.Remove(socket)
	plugin := NewPlugin(resourceName, devicePluginPath, socket, filepath.Base(kubeletSocket), &devicePluginStub{}, log.With(logger, "resource", resourceName), nil)

	ctx, cancel := context.WithCancel(context.Background())

	endSignal := make(chan int)
	var g run.Group

	{
		g.Add(func() error {
			for {
				select {
				case <-endSignal:
					return nil
				// after restarts no error.
				case <-time.After(restartInterval*maxRestartTimes + testBuffer):
					cancel()
					return nil
				}
			}
		}, func(error) {})
	}

	{
		g.Add(func() error {
			// registers mock device plugin with mock kubelet, start device plugin server, and check socket
			err = plugin.Run(ctx)
			// after restarts still have error
			if err != nil {
				t.Errorf("failed to start device plugin server: %v", err)
				endSignal <- 0
			}
			return err
		}, func(error) {})
	}

	if err := g.Run(); err != nil && err.Error() != "test complete" {
		t.Errorf("run group failed: %v", err)
	}
}

func maybeLogError(f func() error, message string) {
	if err := f(); err != nil {
		klog.Errorf(message+":%+v", err)
	}
}

// waitForServer checks if grpc server is alive
// by making grpc blocking connection to the server socket.
func waitForServer(socket string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	defer cancel()

	conn, err := grpc.DialContext(ctx, socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", addr)
		}),
	)
	if conn != nil {
		conn.Close()
	}

	return errors.Wrapf(err, "Failed dial context at %s", socket)
}
