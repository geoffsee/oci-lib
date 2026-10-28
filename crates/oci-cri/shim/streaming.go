//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/streaming/pkg/httpstream"
	"k8s.io/streaming/pkg/httpstream/spdy"
)

type streamingSession struct {
	Kind        string   `json:"kind"`
	ContainerID string   `json:"container_id"`
	Cmd         []string `json:"cmd"`
	TTY         bool     `json:"tty"`
	Stdin       bool     `json:"stdin"`
	StdinOnce   bool     `json:"stdin_once"`
	Stdout      bool     `json:"stdout"`
	Stderr      bool     `json:"stderr"`
	IP          string   `json:"ip"`
}

// Rust has already authenticated the single-use token and read the HTTP header.
// This response writer hands the socket to Kubernetes' SPDY implementation.
type upgradeWriter struct {
	conn    net.Conn
	reader  *bufio.Reader
	header  http.Header
	written bool
}

func (w *upgradeWriter) Header() http.Header { return w.header }
func (w *upgradeWriter) WriteHeader(code int) {
	if w.written {
		return
	}
	w.written = true
	_, _ = fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	_ = w.header.Write(w.conn)
	_, _ = io.WriteString(w.conn, "\r\n")
}
func (w *upgradeWriter) Write(body []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.conn.Write(body)
}
func (w *upgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(w.reader, bufio.NewWriter(w.conn)), nil
}

type incomingStream struct {
	stream  httpstream.Stream
	replied <-chan struct{}
}

func opSPDY(req *opRequest) error {
	fd, err := unix.Dup(req.FD)
	if err != nil {
		return fail(codeRun, "duplicate streaming socket", err.Error())
	}
	file := os.NewFile(uintptr(fd), "cri-stream")
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		return fail(codeRun, "streaming socket", err.Error())
	}
	defer conn.Close()
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(req.Header), conn))
	request, err := http.ReadRequest(reader)
	if err != nil {
		return fail(codeInvalid, "streaming request", err.Error())
	}
	writer := &upgradeWriter{conn: conn, reader: reader, header: make(http.Header)}
	protocols := []string{"v4.channel.k8s.io", "v3.channel.k8s.io", "v2.channel.k8s.io", "channel.k8s.io"}
	if req.Session.Kind == "port_forward" {
		protocols = []string{"portforward.k8s.io"}
	}
	protocol, err := httpstream.Handshake(request, writer, protocols)
	if err != nil {
		return err
	}
	incoming := make(chan incomingStream, 16)
	closed := make(chan struct{})
	defer close(closed)
	upgraded := spdy.NewResponseUpgrader().UpgradeResponse(writer, request, func(stream httpstream.Stream, replied <-chan struct{}) error {
		select {
		case incoming <- incomingStream{stream, replied}:
			return nil
		case <-closed:
			return net.ErrClosed
		}
	})
	if upgraded == nil {
		return fail(codeRun, "SPDY upgrade failed", "")
	}
	defer upgraded.Close()
	upgraded.SetIdleTimeout(5 * time.Minute)
	if req.Session.Kind == "port_forward" {
		return forwardSPDY(req, upgraded, incoming)
	}
	streams := map[string]httpstream.Stream{}
	needed := map[string]bool{"error": true}
	if req.Session.Stdin {
		needed["stdin"] = true
	}
	if req.Session.Stdout {
		needed["stdout"] = true
	}
	if req.Session.Stderr && !req.Session.TTY {
		needed["stderr"] = true
	}
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	for len(needed) > 0 {
		select {
		case item := <-incoming:
			select {
			case <-item.replied:
			case <-upgraded.CloseChan():
				return nil
			}
			kind := item.stream.Headers().Get("streamType")
			if streams[kind] != nil {
				return fail(codeInvalid, "duplicate streaming channel", kind)
			}
			streams[kind] = item.stream
			delete(needed, kind)
		case <-upgraded.CloseChan():
			return nil
		case <-timer.C:
			return fail(codeRun, "timed out waiting for streaming channels", "")
		}
	}
	defer func() {
		for _, stream := range streams {
			_ = stream.Close()
		}
	}()
	var code int
	if req.Session.Kind == "attach" {
		err = attachSPDY(req, upgraded, streams)
	} else {
		execution := *req
		execution.ID, execution.Cmd, execution.TTY = req.Session.ContainerID, req.Session.Cmd, req.Session.TTY
		hooks := &ioHooks{emit: func(channel int32, data []byte) {
			if channel == 0 {
				if input := streams["stdin"]; input != nil {
					_ = input.Reset()
				}
				return
			}
			name := "stdout"
			if channel == 2 && !req.Session.TTY {
				name = "stderr"
			}
			if output := streams[name]; output != nil {
				_, _ = output.Write(data)
			}
		}}
		if input := streams["stdin"]; input != nil {
			hooks.readInput = input.Read
		}
		var result any
		result, err = opExec(&execution, hooks)
		if result != nil {
			code, _ = result.(map[string]any)["exit_code"].(int)
		}
	}
	status := map[string]any{"status": "Success"}
	if err != nil {
		status = map[string]any{"status": "Failure", "message": err.Error(), "reason": "InternalError", "code": 500}
	}
	if code != 0 {
		status = map[string]any{"status": "Failure", "reason": "NonZeroExitCode", "message": fmt.Sprintf("command exited with code %d", code), "details": map[string]any{"causes": []map[string]string{{"reason": "ExitCode", "message": strconv.Itoa(code)}}}}
	}
	if protocol == "v4.channel.k8s.io" {
		_ = json.NewEncoder(streams["error"]).Encode(status)
	} else if err != nil {
		_, _ = io.WriteString(streams["error"], err.Error())
	}
	return nil
}

func attachSPDY(req *opRequest, conn httpstream.Connection, streams map[string]httpstream.Stream) error {
	h, err := getHandle(req, req.Session.ContainerID)
	if err != nil {
		return err
	}
	file, err := os.Open(req.LogPath)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	if input := streams["stdin"]; input != nil && h.stdin != nil {
		go func() {
			_, _ = io.Copy(h.stdin, input)
			if req.Session.StdinOnce {
				_ = h.stdin.Close()
			}
		}()
	}
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			parts := strings.SplitN(line, " ", 4)
			if len(parts) == 4 {
				name := parts[1]
				if req.Session.TTY {
					name = "stdout"
				}
				if out := streams[name]; out != nil {
					if _, err := io.WriteString(out, logPayload(parts)); err != nil {
						return err
					}
				}
			}
		}
		if readErr == nil {
			continue
		}
		if readErr != io.EOF {
			return readErr
		}
		select {
		case <-conn.CloseChan():
			return nil
		case <-h.waitDone:
			h.pumps.Wait()
			// Drain output written by the final pump before reporting exit.
			rest, _ := io.ReadAll(reader)
			for _, line := range strings.SplitAfter(string(rest), "\n") {
				parts := strings.SplitN(line, " ", 4)
				if len(parts) == 4 {
					if out := streams[parts[1]]; out != nil {
						_, _ = io.WriteString(out, logPayload(parts))
					}
				}
			}
			return nil
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func forwardSPDY(req *opRequest, conn httpstream.Connection, incoming <-chan incomingStream) error {
	pairs := map[string]map[string]httpstream.Stream{}
	var workers sync.WaitGroup
	defer func() { _ = conn.Close(); workers.Wait() }()
	for {
		select {
		case <-conn.CloseChan():
			return nil
		case item := <-incoming:
			select {
			case <-item.replied:
			case <-conn.CloseChan():
				return nil
			}
			headers := item.stream.Headers()
			key := headers.Get("requestID") + ":" + headers.Get("port")
			pair := pairs[key]
			if pair == nil {
				pair = map[string]httpstream.Stream{}
				pairs[key] = pair
			}
			pair[headers.Get("streamType")] = item.stream
			if pair["data"] == nil || pair["error"] == nil {
				continue
			}
			delete(pairs, key)
			port, err := strconv.ParseUint(headers.Get("port"), 10, 16)
			if err != nil || port == 0 {
				_, _ = io.WriteString(pair["error"], "invalid port")
				_ = pair["error"].Close()
				_ = pair["data"].Reset()
				continue
			}
			workers.Add(1)
			go func(data, errors httpstream.Stream, port uint64) {
				defer workers.Done()
				defer data.Close()
				defer errors.Close()
				target, err := net.DialTimeout("tcp", net.JoinHostPort(req.Session.IP, strconv.FormatUint(port, 10)), 10*time.Second)
				if err != nil {
					_, _ = io.WriteString(errors, err.Error())
					return
				}
				defer target.Close()
				closed := make(chan struct{})
				defer close(closed)
				go func() {
					select {
					case <-conn.CloseChan():
						_ = target.Close()
					case <-closed:
					}
				}()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(target, data); _ = target.(*net.TCPConn).CloseWrite(); close(done) }()
				_, _ = io.Copy(data, target)
				_ = data.Reset()
				_ = target.Close()
				<-done
			}(pair["data"], pair["error"], port)
		}
	}
}

// CRI adds a record newline even when the original output had none.
func logPayload(parts []string) string {
	if parts[2] == "P" {
		return strings.TrimSuffix(parts[3], "\n")
	}
	return parts[3]
}
