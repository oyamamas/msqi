package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseSSHConnectionString(t *testing.T) {
	for _, tc := range []struct {
		input, address string
		port           int
	}{
		{"user@host", "user@host", 0}, {"alias", "alias", 0},
		{"user@host:2222", "user@host", 2222},
		{"user@[2001:db8::1]:2222", "user@2001:db8::1", 2222},
		{"[::1]", "::1", 0}, {"user@::1", "user@::1", 0},
	} {
		t.Run(tc.input, func(t *testing.T) {
			address, port, err := parseSSHConnectionString(tc.input)
			if err != nil || address != tc.address || port != tc.port {
				t.Fatalf("got %q %d %v", address, port, err)
			}
		})
	}
	for _, input := range []string{"", "-oProxyCommand=x", "u@-host", "@host", "u@@host", "u@", "host:", "host:abc", "host:0", "host:65536", "host:22:33", "[::1", "[host]:22", "[::1]:abc", "host name", "ssh://host"} {
		t.Run("invalid_"+input, func(t *testing.T) {
			if _, _, err := parseSSHConnectionString(input); err == nil {
				t.Fatalf("accepted %q", input)
			}
		})
	}
}

func socksListener(t *testing.T, reply [2]byte) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go serveSOCKS(listener, reply)
	return listener
}

func serveSOCKS(listener net.Listener, reply [2]byte) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			var greeting [3]byte
			if _, err := io.ReadFull(conn, greeting[:]); err == nil && greeting == [3]byte{5, 1, 0} {
				_, _ = conn.Write(reply[:])
			}
		}()
	}
}

func listenerPort(l net.Listener) int { return l.Addr().(*net.TCPAddr).Port }

func TestSOCKSProbeRejectsNonSOCKSAndClosedPorts(t *testing.T) {
	good := socksListener(t, [2]byte{5, 0})
	if err := probeSOCKS(context.Background(), listenerPort(good)); err != nil {
		t.Fatal(err)
	}
	bad := socksListener(t, [2]byte{'H', 'T'})
	if err := probeSOCKS(context.Background(), listenerPort(bad)); err == nil {
		t.Fatal("accepted a non-SOCKS service")
	}
	port := listenerPort(good)
	_ = good.Close()
	if err := probeSOCKS(context.Background(), port); err == nil {
		t.Fatal("accepted a closed port")
	}
}

func TestSOCKSProbeCancellation(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- probeSOCKS(ctx, listenerPort(listener)) }()
	conn := <-accepted
	defer conn.Close()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected cancellation")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("probe ignored cancellation")
	}
}

func TestAttachedTunnelCleanupIsSafe(t *testing.T) {
	listener := socksListener(t, [2]byte{5, 0})
	tun := &tunnel{port: listenerPort(listener)}
	if err := tun.close(); err != nil {
		t.Fatal(err)
	}
	if err := probeSOCKS(context.Background(), tun.port); err != nil {
		t.Fatalf("external tunnel was stopped: %v", err)
	}
}

// Execute this test binary as the SSH child. It can fail before binding, wait
// forever, or serve SOCKS, without an SSH server or real credentials.
func TestSSHHelperProcess(t *testing.T) {
	if os.Getenv("MSQI_TEST_SSH") != "1" {
		return
	}
	destination := os.Args[len(os.Args)-1]
	if err := os.WriteFile(filepath.Join(os.Getenv("MSQI_TEST_SSH_DIR"), destination+".pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		os.Exit(3)
	}
	if destination == "fail.test" {
		fmt.Fprintln(os.Stderr, "authentication failed")
		os.Exit(255)
	}
	if destination == "hang.test" {
		time.Sleep(time.Minute)
		os.Exit(4)
	}
	var address string
	for i, arg := range os.Args {
		if arg == "-D" && i+1 < len(os.Args) {
			address = os.Args[i+1]
		}
	}
	if address == "" {
		os.Exit(5)
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		os.Exit(6)
	}
	serveSOCKS(listener, [2]byte{5, 0})
	os.Exit(0)
}

func mockSSH(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	quoted := "'" + strings.ReplaceAll(executable, "'", "'\\''") + "'"
	script := "#!/bin/sh\nexec " + quoted + " -test.run=^TestSSHHelperProcess$ -- \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("MSQI_TEST_SSH", "1")
	t.Setenv("MSQI_TEST_SSH_DIR", dir)
	return dir
}

func TestSSHStartupAndShutdown(t *testing.T) {
	mockSSH(t)
	tun, err := startSSHTunnel(context.Background(), "ready.test", 3*time.Second, map[int]bool{1337: true}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.close() })
	if err := probeSOCKS(context.Background(), tun.port); err != nil {
		t.Fatal(err)
	}
	if err := tun.close(); err != nil {
		t.Fatal(err)
	}
	if !tun.exited() {
		t.Fatal("child not reaped")
	}
	if err := tun.close(); err != nil {
		t.Fatal(err)
	}
}

func TestFailedSSHIsNeverReady(t *testing.T) {
	mockSSH(t)
	tun, err := startSSHTunnel(context.Background(), "fail.test", 3*time.Second, nil, io.Discard)
	if err == nil || tun != nil || !strings.Contains(err.Error(), "255") {
		t.Fatalf("failed SSH accepted: %v %v", tun, err)
	}
}

func TestSSHReadinessTimeoutReapsChild(t *testing.T) {
	dir := mockSSH(t)
	tun, err := startSSHTunnel(context.Background(), "hang.test", time.Second, nil, io.Discard)
	if err == nil || tun != nil {
		t.Fatalf("unready SSH accepted: %v %v", tun, err)
	}
	assertChildStopped(t, dir, "hang.test")
}

func assertChildStopped(t *testing.T, dir, destination string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, destination+".pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	defer process.Release()
	if err := process.Signal(syscall.Signal(0)); err == nil {
		t.Errorf("child %d is still alive", pid)
		_ = process.Kill()
	}
}
