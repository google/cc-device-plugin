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
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

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
	ccResource := "google.com/cc"
	ccDevicePaths := []string{"/dev/tpmrm0"}
	ccMeasurmentPaths := []string{"/sys/kernel/security/tpm0/binary_bios_measurements"}

	devicePluginPath := v1beta1.DevicePluginPath

	// by default, only track warning and error log
	logLevel := flag.String("log-level", logLevelWarn, fmt.Sprintf("Log level available values: %s", availableLogLevels))
	listen := flag.String("listen", ":8080", "The listening port for health and metrics.")
	flag.Parse()

	ccDeviceSpec := &deviceplugin.CcDeviceSpec{
		Resource:         ccResource,
		DevicePaths:      ccDevicePaths,
		MeasurementPaths: ccMeasurmentPaths,
	}

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

	var g run.Group
	{
		// Run the HTTP server.
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
					logger.Log("msg", "caught interrupt; gracefully cleaning up; see you next time!")
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

	socketPrefix := "cc-device-plugin"
	socket := filepath.Join(devicePluginPath, fmt.Sprintf("%s-%s-%d.sock", socketPrefix, base64.StdEncoding.EncodeToString([]byte(ccResource)), time.Now().Unix()))
	tp, err := deviceplugin.NewCcDevicePlugin(ccDeviceSpec, devicePluginPath, socket, log.With(logger, "resource", ccDeviceSpec.Resource), prometheus.WrapRegistererWith(prometheus.Labels{"resource": ccDeviceSpec.Resource}, r))
	if err != nil {
		return err
	}

	// Start the cc device plugin server.
	g.Add(func() error {
		logger.Log("msg", fmt.Sprintf("Starting the cc-device-plugin for %q.", ccDeviceSpec.Resource))
		return tp.Run(ctx)
	}, func(error) {
		cancel()
	})

	return g.Run()
}

func main() {
	if err := Main(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
