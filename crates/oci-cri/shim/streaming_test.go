//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"k8s.io/streaming/pkg/httpstream/spdy"
)

func TestSPDYPortForwardAndDisconnect(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		socket, err := target.Accept()
		if err != nil {
			return
		}
		defer socket.Close()
		_, _ = io.Copy(socket, socket)
	}()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	served := make(chan error, 1)
	go func() {
		socket, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer socket.Close()
		file, err := socket.(*net.TCPConn).File()
		if err != nil {
			served <- err
			return
		}
		defer file.Close()
		served <- opSPDY(&opRequest{FD: int(file.Fd()), Session: streamingSession{Kind: "port_forward", IP: "127.0.0.1"}})
	}()
	socket, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	_ = socket.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = fmt.Fprintf(socket, "POST /portforward/token HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\nX-Stream-Protocol-Version: portforward.k8s.io\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(socket), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 {
		t.Fatalf("upgrade: %s", response.Status)
	}
	conn, err := spdy.NewClientConnection(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	headers := http.Header{}
	headers.Set("port", strconv.Itoa(target.Addr().(*net.TCPAddr).Port))
	headers.Set("requestID", "0")
	headers.Set("streamType", "error")
	if _, err := conn.CreateStream(headers); err != nil {
		t.Fatal(err)
	}
	headers.Set("streamType", "data")
	data, err := conn.CreateStream(headers)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(data, "forwarded"); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 9)
	if _, err := io.ReadFull(data, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "forwarded" {
		t.Fatalf("got %q", got)
	}
	_ = conn.Close()
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SPDY server retained a disconnected stream")
	}
	select {
	case <-targetDone:
	case <-time.After(5 * time.Second):
		t.Fatal("forwarded socket leaked")
	}
}

func TestAttachReconstructsPartialLogRecords(t *testing.T) {
	got := logPayload([]string{"now", "stdout", "P", "prompt> \n"}) + logPayload([]string{"now", "stdout", "F", "answer\n"})
	if got != "prompt> answer\n" {
		t.Fatalf("attach changed output bytes: %q", got)
	}
}
