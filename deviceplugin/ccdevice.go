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

// Package deviceplugin provides functions to start a device plugin service
package deviceplugin

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	deviceCheckInterval        = 5 * time.Second
	copiedEventLogDirectory    = "/run/cc-device-plugin"
	copiedEventLogLocation     = "/run/cc-device-plugin/binary_bios_measurements"
	containerEventLogDirectory = "/run/cc-device-plugin"
)

// AttestationType defines if the attestation is based on software emulation or hardware.
type AttestationType string

const (
	SoftwareAttestation AttestationType = "software" // e.g., vTPM
	HardwareAttestation AttestationType = "hardware" // e.g., Intel TDX, AMD SEV-SNP
)

var (
	measurementFileLastUpdate time.Time
)

// CcDeviceSpec defines a cc device type and the paths at which
// it can be found.
type CcDeviceSpec struct {
	Resource         string
	DevicePaths      []string
	MeasurementPaths []string
	DeviceLimit      int             // Number of allocatable instances of this resource
	Type             AttestationType // New flag to explicitly define the device type
}

// CcDevice wraps the v1.beta1.Device type, which has hostPath, containerPath and permission
type CcDevice struct {
	v1beta1.Device
	DeviceSpecs []*v1beta1.DeviceSpec
	Mounts      []*v1beta1.Mount
}

// CcDevicePlugin is a device plugin for cc devices
type CcDevicePlugin struct {
	cds                        *CcDeviceSpec
	ccDevices                  map[string]CcDevice
	logger                     log.Logger
	copiedEventLogDirectory    string
	copiedEventLogLocation     string
	containerEventLogDirectory string
	// this lock prevents data race when kubelet sends multiple requests at the same time
	mu sync.Mutex

	// metrics
	deviceGauge        prometheus.Gauge
	allocationsCounter prometheus.Counter
}

// NewCcDevicePlugin creates a new plugin for a cc device.
func NewCcDevicePlugin(cds *CcDeviceSpec, devicePluginPath string, socket string, logger log.Logger, reg prometheus.Registerer) (Plugin, error) {
	if logger == nil {
		logger = log.NewNopLogger()
	}
	if cds.DeviceLimit <= 0 {
		cds.DeviceLimit = 1 // Default to 1 if not specified
	}

	cdp := &CcDevicePlugin{
		cds:                        cds,
		ccDevices:                  make(map[string]CcDevice),
		logger:                     logger,
		copiedEventLogDirectory:    copiedEventLogDirectory,
		copiedEventLogLocation:     copiedEventLogLocation, // Note: This path is static, used only by vTPM plugin instance.
		containerEventLogDirectory: containerEventLogDirectory,
		deviceGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cc_device_plugin_devices",
			Help: "The number of cc devices managed by this device plugin.",
		}),
		allocationsCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cc_device_plugin_allocations_total",
			Help: "The total number of cc device allocations made by this device plugin.",
		}),
	}

	// Only create the directory if the device type is software-based (e.g., vTPM),
	// as hardware-based devices (TDX/SNP) do not require copying measurement files to /run.
	if cdp.cds.Type == SoftwareAttestation {
		if _, err := os.Stat(cdp.copiedEventLogDirectory); os.IsNotExist(err) {
			// Create the directory
			err = os.MkdirAll(cdp.copiedEventLogDirectory, 0755)
			if err != nil {
				return nil, err
			}
			_ = level.Info(cdp.logger).Log("msg", "Directory created:"+cdp.copiedEventLogDirectory)
		} else {
			_ = level.Info(cdp.logger).Log("msg", "Directory already exists:"+cdp.copiedEventLogDirectory)
		}
	}

	if reg != nil {
		reg.MustRegister(cdp.deviceGauge, cdp.allocationsCounter)
	}

	return NewPlugin(cds.Resource, devicePluginPath, socket, "", cdp, logger, prometheus.WrapRegistererWithPrefix("cc_", reg)), nil
}

func (cdp *CcDevicePlugin) discoverCcDevices() ([]CcDevice, error) {
	var ccDevices []CcDevice
	var foundDevicePaths []string

	// We use foundDevicePaths as an accumulator because a single resource (like TDX)
	// might be represented by multiple device path patterns.
	for _, path := range cdp.cds.DevicePaths {
		matches, err := filepath.Glob(path)
		if err != nil {
			return nil, err
		}
		if len(matches) > 0 {
			_ = level.Info(cdp.logger).Log("msg", "found matching device path(s)", "pattern", path, "matches", strings.Join(matches, ","))
			foundDevicePaths = append(foundDevicePaths, matches...)
		}
	}

	// If no device paths were found for this resource type, simply return an empty list.
	// This is not an error; the node just doesn't have this specific hardware.
	if len(foundDevicePaths) == 0 {
		return nil, nil
	}

	baseDevice := CcDevice{
		Device: v1beta1.Device{
			Health: v1beta1.Healthy,
		},
	}

	for _, matchPath := range foundDevicePaths {
		baseDevice.DeviceSpecs = append(baseDevice.DeviceSpecs, &v1beta1.DeviceSpec{
			HostPath:      matchPath,
			ContainerPath: matchPath,
			Permissions:   "mrw",
		})
	}

	// Measurement files are currently only expected for software-emulated devices (vTPM).
	if cdp.cds.Type == SoftwareAttestation && len(cdp.cds.MeasurementPaths) > 0 {
		var foundMeasurementPath string
		for _, path := range cdp.cds.MeasurementPaths {
			matches, err := filepath.Glob(path)
			if err != nil {
				return nil, err
			}
			if len(matches) > 0 {
				// We only expect one measurement file
				foundMeasurementPath = matches[0]
				_ = level.Info(cdp.logger).Log("msg", "measurement path found", "path", foundMeasurementPath)
				break
			}
		}
		if foundMeasurementPath != "" {
			baseDevice.Mounts = append(baseDevice.Mounts, &v1beta1.Mount{
				HostPath:      cdp.copiedEventLogDirectory,
				ContainerPath: cdp.containerEventLogDirectory,
				ReadOnly:      true,
			})

			fileInfo, err := os.Stat(cdp.copiedEventLogLocation)
			if errors.Is(err, os.ErrNotExist) {
				if err := copyMeasurementFile(foundMeasurementPath, cdp.copiedEventLogLocation); err != nil {
					_ = level.Error(cdp.logger).Log("msg", "failed to copy measurement file", "error", err)
					return nil, err
				}
			} else if err == nil && fileInfo.ModTime().After(measurementFileLastUpdate) {
				// Refresh the copy if the source file has been updated by the kernel since the last copy.
				if err := copyMeasurementFile(foundMeasurementPath, cdp.copiedEventLogLocation); err != nil {
					_ = level.Error(cdp.logger).Log("msg", "failed to re-copy measurement file", "error", err)
					return nil, err
				}
			} else if err != nil {
				_ = level.Error(cdp.logger).Log("msg", "failed to stat copied measurement file", "error", err)
				return nil, err
			}
		} else {
			_ = level.Warn(cdp.logger).Log("msg", "MeasurementPaths specified but no measurement file found", "paths", strings.Join(cdp.cds.MeasurementPaths, ","))
		}
	}

	// Create DeviceLimit instances of the device
	h := sha1.New()
	h.Write([]byte(cdp.cds.Resource))
	baseID := fmt.Sprintf("%x", h.Sum(nil))

	for i := 0; i < cdp.cds.DeviceLimit; i++ {
		cd := baseDevice // Copy the base structure
		// For single-limit devices, ID is baseID. For multi-limit, append index.
		if cdp.cds.DeviceLimit > 1 {
			cd.ID = fmt.Sprintf("%s-%d", baseID, i)
		} else {
			cd.ID = baseID
		}
		ccDevices = append(ccDevices, cd)
	}

	return ccDevices, nil
}

func copyMeasurementFile(src string, dest string) error {
	// get time for src
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	// copy out measurement
	eventlogFile, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	// remove if exist
	err = os.Remove(dest)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	err = os.WriteFile(dest, eventlogFile, 0444)
	if err != nil {
		return err
	}
	measurementFileLastUpdate = sourceInfo.ModTime()
	return nil
}

// refreshDevices updates the devices available to the
// cc device plugin and returns a boolean indicating
// if if the devices are the same ones as before.
func (cdp *CcDevicePlugin) refreshDevices() (bool, error) {
	ccDevices, err := cdp.discoverCcDevices()
	if err != nil {
		return false, fmt.Errorf("failed to discover devices: %v", err)
	}

	cdp.deviceGauge.Set(float64(len(ccDevices)))

	cdp.mu.Lock()
	defer cdp.mu.Unlock()

	old := cdp.ccDevices
	cdp.ccDevices = make(map[string]CcDevice)

	devicesUnchange := true
	// Add the new devices to the map and check
	// if they were in the old map.
	for _, d := range ccDevices {
		cdp.ccDevices[d.ID] = d
		if _, ok := old[d.ID]; !ok {
			devicesUnchange = false
		}
	}
	if len(ccDevices) != len(old) {
		devicesUnchange = false
	}

	if devicesUnchange {
		return true, nil
	}

	// Log if devices were removed
	for k := range old {
		if _, ok := cdp.ccDevices[k]; !ok {
			_ = level.Info(cdp.logger).Log("msg", "device removed", "id", k)
		}
	}
	// Log if devices were added
	for k := range cdp.ccDevices {
		if _, ok := old[k]; !ok {
			_ = level.Info(cdp.logger).Log("msg", "device added", "id", k)
		}
	}

	return false, nil
}

// Allocate assigns cc devices to a Pod.
func (cdp *CcDevicePlugin) Allocate(_ context.Context, req *v1beta1.AllocateRequest) (*v1beta1.AllocateResponse, error) {
	cdp.mu.Lock()
	defer cdp.mu.Unlock()
	res := &v1beta1.AllocateResponse{
		ContainerResponses: make([]*v1beta1.ContainerAllocateResponse, 0, len(req.ContainerRequests)),
	}
	for _, r := range req.ContainerRequests {
		resp := new(v1beta1.ContainerAllocateResponse)
		// Add all requested devices and measurements to response.
		for _, id := range r.DevicesIDs {
			ccDevice, ok := cdp.ccDevices[id]
			if !ok {
				return nil, fmt.Errorf("requested cc device does not exist %q", id)
			}
			if ccDevice.Health != v1beta1.Healthy {
				return nil, fmt.Errorf("requested cc device is not healthy %q", id)
			}
			_ = level.Info(cdp.logger).Log("msg", "adding device and measurement to Pod", "device id", id)

			for _, ds := range ccDevice.DeviceSpecs {
				_ = level.Debug(cdp.logger).Log("msg", "added ccDevice.deviceSpecs", "spec", ds.String())
			}

			for _, dm := range ccDevice.Mounts {
				_ = level.Debug(cdp.logger).Log("msg", "added ccDevice.mounts", "mount", dm.String())
			}

			resp.Devices = append(resp.Devices, ccDevice.DeviceSpecs...)
			resp.Mounts = append(resp.Mounts, ccDevice.Mounts...)
		}
		res.ContainerResponses = append(res.ContainerResponses, resp)
	}
	cdp.allocationsCounter.Add(float64(len(res.ContainerResponses)))
	return res, nil
}

// GetDevicePluginOptions returns options to be communicated with Device Manager. Currently it always returns an empty response until plugin options are implemented.
func (cdp *CcDevicePlugin) GetDevicePluginOptions(_ context.Context, _ *v1beta1.Empty) (*v1beta1.DevicePluginOptions, error) {
	return &v1beta1.DevicePluginOptions{}, nil
}

// ListAndWatch lists all devices and then refreshes every deviceCheckInterval.
func (cdp *CcDevicePlugin) ListAndWatch(_ *v1beta1.Empty, stream v1beta1.DevicePlugin_ListAndWatchServer) error {
	_ = level.Info(cdp.logger).Log("msg", "starting list and watch")
	if _, err := cdp.refreshDevices(); err != nil {
		return err
	}

	for {
		res := new(v1beta1.ListAndWatchResponse)
		cdp.mu.Lock()
		for _, dev := range cdp.ccDevices {
			res.Devices = append(res.Devices, &v1beta1.Device{ID: dev.ID, Health: dev.Health})
		}
		cdp.mu.Unlock()

		if err := stream.Send(res); err != nil {
			_ = level.Error(cdp.logger).Log("msg", "failed to send ListAndWatchResponse", "error", err)
			return err
		}

		<-time.After(deviceCheckInterval)

		if _, err := cdp.refreshDevices(); err != nil {
			_ = level.Error(cdp.logger).Log("msg", "error during device refresh", "error", err)
			// Don't return error immediately, try to continue
		}
	}
}

// PreStartContainer is called, if indicated by Device Plugin during registration phase, before each container start. Device plugin can run device specific operations such as resetting the device before making devices available to the container. It is not needed for cc device plugin, thus always returns an empty response.
func (cdp *CcDevicePlugin) PreStartContainer(_ context.Context, _ *v1beta1.PreStartContainerRequest) (*v1beta1.PreStartContainerResponse, error) {
	return &v1beta1.PreStartContainerResponse{}, nil
}

// GetPreferredAllocation returns a preferred set of devices to allocate from a list of available ones. It is only designed to help the devicemanager make a more informed allocation decision when possible. It is not needed for cc device plugin, thus always returns an empty response.
func (cdp *CcDevicePlugin) GetPreferredAllocation(context.Context, *v1beta1.PreferredAllocationRequest) (*v1beta1.PreferredAllocationResponse, error) {
	return &v1beta1.PreferredAllocationResponse{}, nil
}
