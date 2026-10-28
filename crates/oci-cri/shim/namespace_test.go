//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPinnedNamespacesSurviveExitedThreadLeader(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "threaded.c")
	binary := filepath.Join(dir, "threaded")
	body := `#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
static void *worker(void *arg) {
    (void)arg;
    usleep(250000);
    puts("leader-exited"); fflush(stdout);
    for (;;) pause();
    return NULL;
}
int main(void) {
    puts("ready"); fflush(stdout);
    if (getchar() == EOF) return 1;
    pthread_t thread;
    if (pthread_create(&thread,NULL,worker,NULL)) return 2;
    pthread_exit(NULL);
}
`
	if err := os.WriteFile(source, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cc", "-pthread", "-o", binary, source).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v: %s", err, output)
	}
	command := exec.Command(binary)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	reader := bufio.NewReader(output)
	if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("ready: %q %v", line, err)
	}
	pinned, err := pinNamespaces(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	defer closeNamespaces(pinned)
	if _, err := input.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "leader-exited\n" {
		t.Fatalf("leader: %q %v", line, err)
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", command.Process.Pid)); !os.IsNotExist(err) {
		t.Fatalf("expected unavailable leader namespace path, got %v", err)
	}
	for name, path := range namespacePaths(pinned) {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("pinned %s: %v", name, err)
		}
	}
}
