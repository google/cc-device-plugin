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
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	deviceCheckInterval = 5 * time.Second
	// By default, GKE allows up to 110 Pods per node on Standard clusters. Standard clusters can be configured to allow up to 256 Pods per node.
	workloadSharedLimit = 256
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
}

// CcDevice wraps the v1.beta1.Device type, which has hostPath, containerPath and permission
type CcDevice struct {
	v1beta1.Device
	DeviceSpecs []*v1beta1.DeviceSpec
	Mounts      []*v1beta1.Mount
	// Limit specifies the cap number of workloads sharing a worker node
	Limit int
}

// CcDevicePlugin is a device plugin for cc devices
type CcDevicePlugin struct {
	cds                        *CcDeviceSpec
	ccDevices                  map[string]CcDevice
	copiedEventLogDirectory    string
	copiedEventLogLocation     string
	containerEventLogDirectory string
	logger                     log.Logger
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

	cdp := &CcDevicePlugin{
		cds:                        cds,
		ccDevices:                  make(map[string]CcDevice),
		logger:                     logger,
		copiedEventLogDirectory:    "/run/cc-device-plugin",
		copiedEventLogLocation:     "/run/cc-device-plugin/binary_bios_measurements",
		containerEventLogDirectory: "/run/cc-device-plugin",
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
	if _, err := os.Stat(cdp.copiedEventLogDirectory); os.IsNotExist(err) {
		// Create the directory
		err = os.Mkdir(cdp.copiedEventLogDirectory, 0755)
		if err != nil {
			return nil, err
		}
		level.Info(cdp.logger).Log("msg", "Directory created:"+cdp.copiedEventLogDirectory)
	} else {
		level.Info(cdp.logger).Log("msg", "Directory already exists:"+cdp.copiedEventLogDirectory)
	}

	if reg != nil {
		reg.MustRegister(cdp.deviceGauge, cdp.allocationsCounter)
	}

	return NewPlugin(cds.Resource, devicePluginPath, socket, "", cdp, logger, prometheus.WrapRegistererWithPrefix("cc_", reg)), nil
}

func (cdp *CcDevicePlugin) discoverCcDevices() ([]CcDevice, error) {
	var ccDevices []CcDevice
	cd := CcDevice{
		Device: v1beta1.Device{
			Health: v1beta1.Healthy,
		},
		// set cap
		Limit: workloadSharedLimit,
	}
	h := sha1.New()
	for _, path := range cdp.cds.DevicePaths {
		matches, err := filepath.Glob(path)
		if err != nil {
			return nil, err
		}
		for _, matchPath := range matches {
			level.Info(cdp.logger).Log("msg", "device path found:"+matchPath)
			cd.DeviceSpecs = append(cd.DeviceSpecs, &v1beta1.DeviceSpec{
				HostPath:      matchPath,
				ContainerPath: matchPath,
				Permissions:   "mrw",
			})
		}
	}

	for _, path := range cdp.cds.MeasurementPaths {
		matches, err := filepath.Glob(path)
		if err != nil {
			return nil, err
		}
		for _, matchPath := range matches {
			level.Info(cdp.logger).Log("msg", "measurement path found:"+matchPath)
			cd.Mounts = append(cd.Mounts, &v1beta1.Mount{
				HostPath:      cdp.copiedEventLogDirectory,
				ContainerPath: cdp.containerEventLogDirectory,
				ReadOnly:      true,
			})

			// copy when no measurement file at copiedEventLogLocation
			fileInfo, err := os.Stat(cdp.copiedEventLogLocation)
			if errors.Is(err, os.ErrNotExist) {
				err := copyMeasurementFile(matchPath, cdp.copiedEventLogLocation)
				if err != nil {
					return nil, err
				}
			} else {
				// copy when measurement file at /run was updated, but not by the current instance.
				// measurementFileLastUpdate is init to 0.
				// when file exists during first run, this instance deletes and creates a new file
				if fileInfo.ModTime().After(measurementFileLastUpdate) {
					err := copyMeasurementFile(matchPath, cdp.copiedEventLogLocation)
					if err != nil {
						return nil, err
					}
				}
			}
		}
	}
	if cd.DeviceSpecs != nil {
		for i := 0; i < cd.Limit; i++ {
			b := make([]byte, 1)
			b[0] = byte(i)
			cd.ID = fmt.Sprintf("%x", h.Sum(b))
			ccDevices = append(ccDevices, cd)
		}
	}

	return ccDevices, nil
}

func copyMeasurementFile(src string, dest string) error {
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
	fileInfo, err := os.Stat(dest)
	if err != nil {
		return err
	}
	measurementFileLastUpdate = fileInfo.ModTime()
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
	if !devicesUnchange {
		return false, nil
	}

	// Check if devices were removed.
	for k := range old {
		if _, ok := cdp.ccDevices[k]; !ok {
			level.Warn(cdp.logger).Log("msg", "devices removed")
			return false, nil
		}
	}
	return true, nil
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
			level.Info(cdp.logger).Log("msg", "adding device and measurement to Pod, device id is:"+id)

			for _, ds := range ccDevice.DeviceSpecs {
				level.Info(cdp.logger).Log("msg", "added ccDevice.deviceSpecs is:"+ds.String())
			}

			for _, dm := range ccDevice.Mounts {
				level.Info(cdp.logger).Log("msg", "added ccDevice.mounts is:"+dm.String())
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
	level.Info(cdp.logger).Log("msg", "starting list and watch")
	if _, err := cdp.refreshDevices(); err != nil {
		return err
	}
	refreshComplete := false
	var err error
	for {
		if !refreshComplete {
			res := new(v1beta1.ListAndWatchResponse)
			for _, dev := range cdp.ccDevices {
				res.Devices = append(res.Devices, &v1beta1.Device{ID: dev.ID, Health: dev.Health})
			}
			if err := stream.Send(res); err != nil {
				return err
			}
		}
		<-time.After(deviceCheckInterval)
		refreshComplete, err = cdp.refreshDevices()
		if err != nil {
			return err
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
