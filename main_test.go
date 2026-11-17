// Copyright 2026 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestHTTPServerBoundsSlowConnections guards against Slowloris: stalled clients
// must not be able to hold an unbounded number of connections.
func TestHTTPServerBoundsSlowConnections(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := l.Addr().String()

	// dialSlow opens a connection that sends a partial request header and stalls.
	dialSlow := func() net.Conn {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("GET /health HTTP/1.1\r\nHost: x\r\n"))
		t.Cleanup(func() { _ = c.Close() })
		return c
	}

	// Occupy every connection slot with a stalled client.
	slow := make([]net.Conn, httpMaxConns)
	for i := range slow {
		slow[i] = dialSlow()
	}

	// A connection beyond the cap is closed right away instead of being held.
	if !closedWithin(dialSlow(), time.Second) {
		t.Error("connection beyond httpMaxConns was not closed")
	}

	// Stalled clients are disconnected once the header timeout elapses.
	if !closedWithin(slow[0], httpReadHeaderTimeout+2*time.Second) {
		t.Error("stalled connection was not closed after httpReadHeaderTimeout")
	}

	// Freed slots are available to legitimate requests again.
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	var resp *http.Response
	for i := 0; i < 20; i++ {
		if resp, err = client.Get("http://" + addr + "/health"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /health after slots were freed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /health = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// closedWithin reports whether the server closes c within d.
func closedWithin(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := io.Copy(io.Discard, c)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false // Still open when the deadline hit.
	}
	return true // EOF or reset: the server closed it.
}
