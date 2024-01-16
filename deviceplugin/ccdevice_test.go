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
	"crypto/sha1"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/metadata"
	"k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	ccResourceName = namespace + "/testccdevicetype"
	testBuffer     = 3 * time.Second
)

var (
	logger log.Logger
)

func init() {
	logger = log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
	logger = level.NewFilter(logger, level.AllowInfo())
	logger = log.With(logger, "timestamp", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

}

func constructCcDevicePlugin(t *testing.T) *CcDevicePlugin {
	ccDevicePath := "/tmp/testccdevice" + t.Name()
	ccMeasurmentPath := "/tmp/testmeasurement" + t.Name()

	ccDevicePaths := []string{ccDevicePath}
	ccMeasurmentPaths := []string{ccMeasurmentPath}

	ccDeviceSpec := &CcDeviceSpec{
		Resource:         ccResourceName,
		DevicePaths:      ccDevicePaths,
		MeasurementPaths: ccMeasurmentPaths,
	}

	testCcDevicePlugin := CcDevicePlugin{
		cds:                        ccDeviceSpec,
		ccDevices:                  make(map[string]CcDevice),
		copiedEventLogDirectory:    "/tmp/cc-device-plugin",
		copiedEventLogLocation:     "/tmp/cc-device-plugin/run_testcopiedmeasurement" + t.Name(),
		containerEventLogDirectory: "/run/cc-device-plugin",
		logger:                     logger,
		deviceGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cc_device_plugin_devices",
			Help: "The number of cc devices managed by this device plugin.",
		}),
		allocationsCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cc_device_plugin_allocations_total",
			Help: "The total number of cc device allocations made by this device plugin.",
		}),
	}

	// Check if the copiedEventLogDirectory directory exists
	if _, err := os.Stat(testCcDevicePlugin.copiedEventLogDirectory); os.IsNotExist(err) {
		// Create the directory
		err = os.Mkdir(testCcDevicePlugin.copiedEventLogDirectory, 0755)
		if err != nil {
			level.Warn(testCcDevicePlugin.logger).Log("msg", "Error creating directory:"+testCcDevicePlugin.copiedEventLogDirectory)
			t.Errorf("failed to create directory: %v", err)
		}
		level.Info(testCcDevicePlugin.logger).Log("msg", "Directory created:"+testCcDevicePlugin.copiedEventLogDirectory)
	} else {
		level.Info(testCcDevicePlugin.logger).Log("msg", "Directory already exists:"+testCcDevicePlugin.copiedEventLogDirectory)
	}

	for _, ccDevicePath := range ccDevicePaths {
		os.Remove(ccDevicePath)
		err := os.WriteFile(ccDevicePath, []byte("TestCcDevice"), 0777)
		if err != nil {
			t.Errorf("failed to WriteFile: %v", err)
		}
	}
	for _, ccMeasurmentPath := range ccMeasurmentPaths {
		os.Remove(ccMeasurmentPath)
		err := os.WriteFile(ccMeasurmentPath, []byte("TestCcDevice"), 0777)
		if err != nil {
			t.Errorf("failed to WriteFile: %v", err)
		}
	}

	os.Remove(testCcDevicePlugin.copiedEventLogLocation)
	return &testCcDevicePlugin
}

func TestDiscoverCcDevices(t *testing.T) {
	testCcDevicePlugin := constructCcDevicePlugin(t)
	gotCcDevices, err := testCcDevicePlugin.discoverCcDevices()
	if err != nil {
		t.Errorf("failed to discoverCcDevices: %v", err)
		return
	}
	// discoverCcDevices copies measurement file, delete after test.
	err = os.Remove(testCcDevicePlugin.copiedEventLogLocation)
	if err != nil {
		t.Errorf("failed to delete: %v", err)
		return
	}

	wantCcDevice := CcDevice{
		Device: v1beta1.Device{
			Health: v1beta1.Healthy,
		},
		DeviceSpecs: []*v1beta1.DeviceSpec{{
			HostPath:      testCcDevicePlugin.cds.DevicePaths[0],
			ContainerPath: testCcDevicePlugin.cds.DevicePaths[0],
			Permissions:   "mrw",
		}},
		Mounts: []*v1beta1.Mount{{
			HostPath:      testCcDevicePlugin.copiedEventLogDirectory,
			ContainerPath: testCcDevicePlugin.containerEventLogDirectory,
			ReadOnly:      true,
		}},
		Limit: workloadSharedLimit,
	}

	var wantCcDevices []CcDevice
	for i := 0; i < wantCcDevice.Limit; i++ {
		wantCcDevices = append(wantCcDevices, wantCcDevice)
	}

	if !cmp.Equal(gotCcDevices, wantCcDevices, cmpopts.IgnoreFields(v1beta1.Device{}, "ID")) {
		t.Errorf("ccDevices do not match expected value: got %v, want %v", gotCcDevices, wantCcDevices)
	}
}

func TestDiscoverCcDevicesPermissionFailure(t *testing.T) {
	testCcDevicePlugin := constructCcDevicePlugin(t)
	testCcDevicePlugin.copiedEventLogDirectory = "/tmp/cc-device-plugin"
	testCcDevicePlugin.copiedEventLogLocation = "/tmp/cc-device-plugin/run_testcopiedmeasurement" + t.Name()
	_, err := testCcDevicePlugin.discoverCcDevices()
	if err != nil && !errors.Is(err, os.ErrPermission) {
		t.Errorf("failed to discoverCcDevices: %v", err)
		return
	}
}

func TestRefreshDevices(t *testing.T) {
	testCcDevicePlugin := constructCcDevicePlugin(t)
	// first time
	wantSameCcDeviceMap := false
	gotSameCcDeviceMap, err := testCcDevicePlugin.refreshDevices()
	if err != nil {
		t.Errorf("refreshDevices failed")
	}
	if gotSameCcDeviceMap != wantSameCcDeviceMap {
		t.Errorf("first time refreshDevices return does not match expected value: got %v, want %v", gotSameCcDeviceMap, wantSameCcDeviceMap)
	}
	wantNumOfCcDevices := workloadSharedLimit
	gotNumOfCcDevices := len(testCcDevicePlugin.ccDevices)
	if len(testCcDevicePlugin.ccDevices) != wantNumOfCcDevices {
		t.Errorf("first time refreshDevices map ccdevices does not match expected value: got %v, want %v", gotNumOfCcDevices, wantNumOfCcDevices)
	}
	os.Remove(testCcDevicePlugin.copiedEventLogLocation)

	// second time
	wantSameCcDeviceMap = true
	gotSameCcDeviceMap, err = testCcDevicePlugin.refreshDevices()
	if err != nil {
		t.Errorf("refreshDevices failed")
	}
	if gotSameCcDeviceMap != wantSameCcDeviceMap {
		t.Errorf("second time refreshDevices return does not match expected value: got %v, want %v", gotSameCcDeviceMap, wantSameCcDeviceMap)
	}
	os.Remove(testCcDevicePlugin.copiedEventLogLocation)

	// third time remove ccDeivces
	wantSameCcDeviceMap = false
	ccDevicePath := "/tmp/testccdevice" + t.Name()
	ccMeasurmentPath := "/tmp/testmeasurement" + t.Name()
	os.Remove(ccDevicePath)
	os.Remove(ccMeasurmentPath)

	gotSameCcDeviceMap, err = testCcDevicePlugin.refreshDevices()
	if err != nil {
		t.Errorf("refreshDevices failed")
	}
	if gotSameCcDeviceMap != wantSameCcDeviceMap {
		t.Errorf("third time refreshDevices return does not match expected value: got %v, want %v", gotSameCcDeviceMap, wantSameCcDeviceMap)
	}
	os.Remove(testCcDevicePlugin.copiedEventLogLocation)
}

func TestAllocate(t *testing.T) {
	testCcDevicePlugin := constructCcDevicePlugin(t)
	_, err := testCcDevicePlugin.refreshDevices()
	if err != nil {
		t.Errorf("refreshDevices failed")
	}

	ctx := context.Background()
	h := sha1.New()
	b := make([]byte, 1)

	for i := 0; i < workloadSharedLimit; i++ {
		b[0] = byte(i)
		req := &v1beta1.AllocateRequest{
			ContainerRequests: []*v1beta1.ContainerAllocateRequest{{
				DevicesIDs: []string{fmt.Sprintf("%x", h.Sum(b))},
			}},
		}
		gotRes, err := testCcDevicePlugin.Allocate(ctx, req)
		if err != nil {
			t.Errorf("Allocate failed")
		}

		ccDevicePath := "/tmp/testccdevice" + t.Name()
		wantRes := &v1beta1.AllocateResponse{
			ContainerResponses: []*v1beta1.ContainerAllocateResponse{{
				Devices: []*v1beta1.DeviceSpec{{
					ContainerPath: ccDevicePath,
					HostPath:      ccDevicePath,
					Permissions:   "mrw",
				}},
				Mounts: []*v1beta1.Mount{{
					ContainerPath: testCcDevicePlugin.containerEventLogDirectory,
					HostPath:      testCcDevicePlugin.copiedEventLogDirectory,
					ReadOnly:      true,
				}},
			}},
		}

		if !cmp.Equal(gotRes, wantRes) {
			t.Errorf("AllocateResponse does not match expected value: got %v, want %v", gotRes, wantRes)
		}
	}
}

func TestAllocateNotExistDevice(t *testing.T) {
	notExsitDeviceName := "NotExistDevice"
	testCcDevicePlugin := constructCcDevicePlugin(t)
	_, err := testCcDevicePlugin.refreshDevices()
	if err != nil {
		t.Errorf("refreshDevices failed")
	}

	ctx := context.Background()
	req := &v1beta1.AllocateRequest{
		ContainerRequests: []*v1beta1.ContainerAllocateRequest{{
			DevicesIDs: []string{notExsitDeviceName},
		}},
	}
	_, err = testCcDevicePlugin.Allocate(ctx, req)
	if err.Error() != "requested cc device does not exist \""+notExsitDeviceName+"\"" {
		t.Errorf("Allocate failed")
	}
}

type listAndWatchServerStub struct {
	testComplete bool
}

func (d *listAndWatchServerStub) Send(*v1beta1.ListAndWatchResponse) error {
	if d.testComplete {
		return errors.New("")
	}
	return nil
}

func (d *listAndWatchServerStub) SetTestComplete() {
	d.testComplete = true
}

func (d *listAndWatchServerStub) SetHeader(metadata.MD) error {
	return nil
}

func (d *listAndWatchServerStub) SendHeader(metadata.MD) error {
	return nil
}

func (d *listAndWatchServerStub) SetTrailer(metadata.MD) {
}

func (d *listAndWatchServerStub) Context() context.Context {
	return context.Background()
}

func (d *listAndWatchServerStub) SendMsg(any) error {
	return nil
}

func (d *listAndWatchServerStub) RecvMsg(any) error {
	return nil
}

// The ListAndWatch function does not stop when no error. We use a timer to stop the
// ListAndWatch function when no error. The ListAndWatch function refresh devices every
// deviceCheckInterval. So the timer waits for deviceCheckInterval. We add a testBuffer
// to timer in case the timer ends before devices are refreshed.
func TestListAndWatch(t *testing.T) {
	testCcDevicePlugin := constructCcDevicePlugin(t)

	stream := listAndWatchServerStub{}

	endSignal := make(chan int)
	var g run.Group

	{
		g.Add(func() error {
			for {
				select {
				case <-endSignal:
					return nil
				// no error.
				case <-time.After(deviceCheckInterval + testBuffer):
					stream.SetTestComplete()
					ccDevicePath := "/tmp/testccdevice" + t.Name()
					ccMeasurmentPath := "/tmp/testmeasurement" + t.Name()
					os.Remove(ccDevicePath)
					os.Remove(ccMeasurmentPath)
					return nil
				}
			}
		}, func(error) {})
	}

	{
		g.Add(func() error {
			err := testCcDevicePlugin.ListAndWatch(&v1beta1.Empty{}, &stream)
			if err != nil {
				if err.Error() != "" {
					t.Errorf("ListAndWatch failed")
					endSignal <- 0
				} else {
					return nil
				}
			}
			return err
		}, func(error) {})
	}

	g.Run()
}
