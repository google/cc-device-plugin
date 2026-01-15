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
	"path/filepath"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/metadata"
	"k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	testBuffer = 3 * time.Second
)

var (
	logger log.Logger
)

func init() {
	logger = log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
	logger = level.NewFilter(logger, level.AllowAll())
	logger = log.With(logger, "timestamp", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)
}

// constructTestPlugin creates a *CcDevicePlugin using a temporary directory for isolation.
func constructTestPlugin(t *testing.T, spec *CcDeviceSpec) *CcDevicePlugin {
	t.Helper()
	tmpDir := t.TempDir()

	// Create dummy device files
	for idx, path := range spec.DevicePaths {
		absPath := filepath.Join(tmpDir, path)
		if err := os.MkdirAll(filepath.Dir(absPath), 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		if err := os.WriteFile(absPath, []byte("test_device"), 0644); err != nil {
			t.Fatalf("failed to create mock device: %v", err)
		}
		spec.DevicePaths[idx] = absPath
	}

	// Create dummy measurement files
	for idx, path := range spec.MeasurementPaths {
		absPath := filepath.Join(tmpDir, path)
		if err := os.MkdirAll(filepath.Dir(absPath), 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		if err := os.WriteFile(absPath, []byte("test_measurement"), 0644); err != nil {
			t.Fatalf("failed to create mock measurement: %v", err)
		}
		spec.MeasurementPaths[idx] = absPath
	}

	cdp := &CcDevicePlugin{
		cds:                        spec,
		ccDevices:                  make(map[string]CcDevice),
		logger:                     logger,
		copiedEventLogDirectory:    filepath.Join(tmpDir, "run/cc-device-plugin"),
		copiedEventLogLocation:     filepath.Join(tmpDir, "run/cc-device-plugin/binary_bios_measurements"),
		containerEventLogDirectory: "/run/cc-device-plugin",
		deviceGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "test_cc_devices_" + t.Name(),
		}),
		allocationsCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "test_cc_allocations_" + t.Name(),
		}),
	}

	// For SoftwareAttestation, we expect the directory to be created
	if spec.Type == SoftwareAttestation {
		if err := os.MkdirAll(cdp.copiedEventLogDirectory, 0755); err != nil {
			t.Fatalf("failed to create directory: %v", err)
		}
	}

	return cdp
}

func getExpectedID(resourceName string, limit int, index int) string {
	h := sha1.New()
	h.Write([]byte(resourceName))
	baseID := fmt.Sprintf("%x", h.Sum(nil))
	if limit > 1 {
		return fmt.Sprintf("%s-%d", baseID, index)
	}
	return baseID
}

func TestDiscoverTDX(t *testing.T) {
	spec := &CcDeviceSpec{
		Resource:    "intel.com/tdx",
		Type:        HardwareAttestation,
		DevicePaths: []string{"dev/tdx-guest"},
		DeviceLimit: 1,
	}
	cdp := constructTestPlugin(t, spec)
	devices, err := cdp.discoverCcDevices()
	if err != nil {
		t.Fatalf("discoverCcDevices failed: %v", err)
	}

	if len(devices) != 1 {
		t.Fatalf("Expected 1 device, got %d", len(devices))
	}
	// Hardware-based should NOT have mounts
	if len(devices[0].Mounts) != 0 {
		t.Errorf("TDX should have 0 mounts, got %d", len(devices[0].Mounts))
	}
}

func TestDiscoverSEVSNP(t *testing.T) {
	spec := &CcDeviceSpec{
		Resource:    "amd.com/sev-snp",
		Type:        HardwareAttestation,
		DevicePaths: []string{"dev/sev-guest"},
		DeviceLimit: 1,
	}
	cdp := constructTestPlugin(t, spec)
	devices, err := cdp.discoverCcDevices()
	if err != nil {
		t.Fatalf("discoverCcDevices failed: %v", err)
	}

	if len(devices) != 1 {
		t.Fatalf("Expected 1 device, got %d", len(devices))
	}
	if len(devices[0].Mounts) != 0 {
		t.Errorf("SEV-SNP should have 0 mounts, got %d", len(devices[0].Mounts))
	}
}

func TestDiscoverTPM(t *testing.T) {
	spec := &CcDeviceSpec{
		Resource:         "google.com/cc",
		Type:             SoftwareAttestation,
		DevicePaths:      []string{"dev/tpmrm0"},
		MeasurementPaths: []string{"sys/binary_bios_measurements"},
		DeviceLimit:      256,
	}
	cdp := constructTestPlugin(t, spec)
	devices, err := cdp.discoverCcDevices()
	if err != nil {
		t.Fatalf("discoverCcDevices failed: %v", err)
	}

	if len(devices) != 256 {
		t.Fatalf("Expected 256 devices, got %d", len(devices))
	}

	// Software-based (vTPM) SHOULD have mounts
	if len(devices[0].Mounts) == 0 {
		t.Errorf("TPM should have mounts for event log copying")
	}

	// Verify file was actually copied to the temporary "run" dir
	if _, err := os.Stat(cdp.copiedEventLogLocation); err != nil {
		t.Errorf("Measurement file was not copied to target location: %v", err)
	}
}

func TestRefreshDevices(t *testing.T) {
	spec := &CcDeviceSpec{
		Resource:    "intel.com/tdx",
		Type:        HardwareAttestation,
		DevicePaths: []string{"dev/tdx-guest"},
		DeviceLimit: 1,
	}
	cdp := constructTestPlugin(t, spec)
	devPath := spec.DevicePaths[0]

	// 1. Initial Refresh
	changed, err := cdp.refreshDevices()
	if err != nil || changed {
		t.Errorf("First refresh: err=%v, changed=%v (want false)", err, changed)
	}

	// 2. Second Refresh (No change)
	changed, err = cdp.refreshDevices()
	if err != nil || !changed {
		t.Errorf("Second refresh: err=%v, changed=%v (want true)", err, changed)
	}

	// 3. Remove device and refresh
	os.Remove(devPath)
	changed, err = cdp.refreshDevices()
	if err != nil || changed {
		t.Errorf("Third refresh (removed): err=%v, changed=%v (want false)", err, changed)
	}
	if len(cdp.ccDevices) != 0 {
		t.Errorf("Expected 0 devices, got %d", len(cdp.ccDevices))
	}
}

func TestAllocate(t *testing.T) {
	spec := &CcDeviceSpec{
		Resource:         "google.com/cc",
		Type:             SoftwareAttestation,
		DevicePaths:      []string{"dev/tpmrm0"},
		MeasurementPaths: []string{"sys/binary_bios_measurements"},
		DeviceLimit:      2,
	}
	cdp := constructTestPlugin(t, spec)
	if _, err := cdp.refreshDevices(); err != nil {
		t.Fatalf("refreshDevices failed: %v", err)
	}

	ctx := context.Background()
	expectedID := getExpectedID(spec.Resource, spec.DeviceLimit, 0)

	req := &v1beta1.AllocateRequest{
		ContainerRequests: []*v1beta1.ContainerAllocateRequest{{
			DevicesIDs: []string{expectedID},
		}},
	}

	resp, err := cdp.Allocate(ctx, req)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}

	if len(resp.ContainerResponses) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(resp.ContainerResponses))
	}

	// Verify the response contains the mount for software attestation
	if len(resp.ContainerResponses[0].Mounts) == 0 {
		t.Errorf("Expected mount in AllocateResponse for software attestation")
	}
}

func TestAllocateNotExistDevice(t *testing.T) {
	spec := &CcDeviceSpec{Resource: "test", Type: HardwareAttestation}
	cdp := constructTestPlugin(t, spec)

	req := &v1beta1.AllocateRequest{
		ContainerRequests: []*v1beta1.ContainerAllocateRequest{{
			DevicesIDs: []string{"NonExistentID"},
		}},
	}
	_, err := cdp.Allocate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for non-existent device, got nil")
	}
}

type listAndWatchServerStub struct {
	testComplete bool
}

func (d *listAndWatchServerStub) Send(*v1beta1.ListAndWatchResponse) error {
	if d.testComplete {
		return errors.New("test complete")
	}
	return nil
}

func (d *listAndWatchServerStub) SetTestComplete()             { d.testComplete = true }
func (d *listAndWatchServerStub) SetHeader(metadata.MD) error  { return nil }
func (d *listAndWatchServerStub) SendHeader(metadata.MD) error { return nil }
func (d *listAndWatchServerStub) SetTrailer(metadata.MD)       { /* no-op for testing */ }
func (d *listAndWatchServerStub) Context() context.Context     { return context.Background() }
func (d *listAndWatchServerStub) SendMsg(any) error            { return nil }
func (d *listAndWatchServerStub) RecvMsg(any) error            { return nil }

func TestListAndWatch(t *testing.T) {
	spec := &CcDeviceSpec{
		Resource:    "intel.com/tdx",
		Type:        HardwareAttestation,
		DevicePaths: []string{"dev/tdx-guest"},
		DeviceLimit: 1,
	}
	cdp := constructTestPlugin(t, spec)
	stream := listAndWatchServerStub{}
	endSignal := make(chan struct{})
	var g run.Group

	{
		g.Add(func() error {
			select {
			case <-endSignal:
				return nil
			case <-time.After(deviceCheckInterval + testBuffer):
				stream.SetTestComplete()
				os.Remove(spec.DevicePaths[0])
				return nil
			}
		}, func(error) {})
	}

	{
		g.Add(func() error {
			err := cdp.ListAndWatch(&v1beta1.Empty{}, &stream)
			if err != nil && err.Error() != "test complete" {
				t.Errorf("ListAndWatch failed: %v", err)
				close(endSignal)
			}
			return nil
		}, func(error) {})
	}

	if err := g.Run(); err != nil && err.Error() != "test complete" {
		t.Errorf("run group failed: %v", err)
	}
}
