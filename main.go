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

// Package main starts a cc device plugin service
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	flag "github.com/spf13/pflag"
	"k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"

	"github.com/google/cc-device-plugin/deviceplugin"
)

const (
	logLevelAll   = "all"
	logLevelDebug = "debug"
	logLevelInfo  = "info"
	logLevelWarn  = "warn"
	logLevelError = "error"
	logLevelNone  = "none"
)

var (
	availableLogLevels = strings.Join([]string{
		logLevelAll,
		logLevelDebug,
		logLevelInfo,
		logLevelWarn,
		logLevelError,
		logLevelNone,
	}, ", ")
)

// Main is the principal function for the binary, wrapped only by `main` for convenience.
func Main() error {
	// We create a list of specs, one for each device type.
	allDeviceSpecs := []*deviceplugin.CcDeviceSpec{
		{
			// vTPM for standard Confidential VMs
			Resource:         "google.com/cc",
			Type:             deviceplugin.SoftwareAttestation, // Explicitly marked as software
			DevicePaths:      []string{"/dev/tpmrm0"},
			MeasurementPaths: []string{"/sys/kernel/security/tpm0/binary_bios_measurements"},
			DeviceLimit:      256, // Allow multiple pods to share the vTPM
		},
		{
			// Intel TDX
			Resource:    "intel.com/tdx",
			Type:        deviceplugin.HardwareAttestation,             // Explicitly marked as hardware
			DevicePaths: []string{"/dev/tdx-guest", "/dev/tdx_guest"}, // Some kernels use different names
			// TDX does not have a separate measurement file, attestation is done via ioctl.
			MeasurementPaths: []string{},
			DeviceLimit:      1, // Only one container can use the TDX device at a time per node
		},
		{
			// AMD SEV-SNP
			Resource:    "amd.com/sev-snp",
			Type:        deviceplugin.HardwareAttestation, // Explicitly marked as hardware
			DevicePaths: []string{"/dev/sev-guest"},
			// SEV-SNP also uses ioctl for attestation.
			MeasurementPaths: []string{},
			DeviceLimit:      1, // Only one container can use the SEV-SNP device at a time per node
		},
	}

	devicePluginPath := v1beta1.DevicePluginPath
	socketPrefix := "cc-device-plugin"

	// by default, only track warning and error log
	logLevel := flag.String("log-level", logLevelWarn, fmt.Sprintf("Log level available values: %s", availableLogLevels))
	listen := flag.String("listen", ":8080", "The listening port for health and metrics.")
	flag.Parse()

	logger := log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
	switch *logLevel {
	case logLevelAll:
		logger = level.NewFilter(logger, level.AllowAll())
	case logLevelDebug:
		logger = level.NewFilter(logger, level.AllowDebug())
	case logLevelInfo:
		logger = level.NewFilter(logger, level.AllowInfo())
	case logLevelWarn:
		logger = level.NewFilter(logger, level.AllowWarn())
	case logLevelError:
		logger = level.NewFilter(logger, level.AllowError())
	case logLevelNone:
		logger = level.NewFilter(logger, level.AllowNone())
	default:
		return fmt.Errorf("log level %v unknown; available values are: %s", *logLevel, availableLogLevels)
	}
	logger = log.With(logger, "timestamp", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	r := prometheus.NewRegistry()
	r.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	// Defer socket cleanup
	defer func() {
		_ = level.Info(logger).Log("msg", "Cleaning up potential socket files")
		for _, spec := range allDeviceSpecs {
			safeResourceName := strings.ReplaceAll(spec.Resource, "/", "-")
			socketPath := filepath.Join(devicePluginPath, fmt.Sprintf("%s-%s.sock", socketPrefix, safeResourceName))
			if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
				_ = level.Warn(logger).Log("msg", "Failed to remove socket file", "path", socketPath, "error", err)
			}
		}
	}()

	var g run.Group
	{
		// Run the HTTP server for metrics and health checks.
		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		mux.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
		l, err := net.Listen("tcp", *listen)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %v", *listen, err)
		}

		g.Add(func() error {
			if err := http.Serve(l, mux); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("server exited unexpectedly: %v", err)
			}
			return nil
		}, func(error) {
			l.Close()
		})
	}

	{
		// Exit gracefully on SIGINT and SIGTERM.
		term := make(chan os.Signal, 1)
		signal.Notify(term, syscall.SIGINT, syscall.SIGTERM)
		cancel := make(chan struct{})
		g.Add(func() error {
			for {
				select {
				case <-term:
					_ = level.Info(logger).Log("msg", "caught interrupt; gracefully cleaning up; see you next time!")
					return nil
				case <-cancel:
					return nil
				}
			}
		}, func(error) {
			close(cancel)
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pluginCreationErrors := false
	// The run.Group `g` will manage all of them concurrently.
	for _, spec := range allDeviceSpecs {
		// Use a local variable for the spec in the closure
		ccDeviceSpec := spec
		safeResourceName := strings.ReplaceAll(ccDeviceSpec.Resource, "/", "-")
		socket := filepath.Join(devicePluginPath, fmt.Sprintf("%s-%s.sock", socketPrefix, safeResourceName))

		// Create a new device plugin instance for the current device spec
		p, err := deviceplugin.NewCcDevicePlugin(ccDeviceSpec, devicePluginPath, socket, log.With(logger, "resource", ccDeviceSpec.Resource), prometheus.WrapRegistererWith(prometheus.Labels{"resource": ccDeviceSpec.Resource}, r))
		if err != nil {
			_ = level.Error(logger).Log("msg", "Failed to create new device plugin", "resource", ccDeviceSpec.Resource, "error", err)
			pluginCreationErrors = true // Mark that at least one plugin failed
			continue
		}

		// Add the device plugin server to the run.Group
		g.Add(func() error {
			_ = level.Info(logger).Log("msg", "Starting the cc-device-plugin", "resource", ccDeviceSpec.Resource)
			return p.Run(ctx)
		}, func(error) {
			// This will be called on shutdown, ensuring the context is cancelled for this plugin instance.
			cancel()
		})
	}

	if err := g.Run(); err != nil {
		return err
	}

	if pluginCreationErrors {
		return fmt.Errorf("one or more device plugins failed to initialize")
	}

	return nil
}

func main() {
	if err := Main(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
