package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testConfig(t *testing.T) proxyConfig {
	t.Helper()
	port, err := allocateTunnelPort(nil)
	if err != nil {
		t.Fatal(err)
	}
	return proxyConfig{port: port, startupTimeout: 3 * time.Second, healthInterval: 50 * time.Millisecond}
}

func waitUpdate(t *testing.T, m *fakeFirewall) string {
	t.Helper()
	select {
	case update := <-m.updates:
		return update
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for firewall update")
		return ""
	}
}

func waitProxy(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not shut down")
		return nil
	}
}

func TestProxyConfigValidation(t *testing.T) {
	base := proxyConfig{port: 1337, attach: []int{1444}, startupTimeout: time.Second, healthInterval: time.Second}
	for _, tc := range []struct {
		name   string
		change func(*proxyConfig)
	}{
		{"port zero", func(c *proxyConfig) { c.port = 0 }},
		{"port overflow", func(c *proxyConfig) { c.port = 65536 }},
		{"no tunnels", func(c *proxyConfig) { c.attach = nil }},
		{"attach facade", func(c *proxyConfig) { c.attach = []int{1337} }},
		{"duplicate attach", func(c *proxyConfig) { c.attach = []int{1444, 1444} }},
		{"bad attach", func(c *proxyConfig) { c.attach = []int{-1} }},
		{"bad SSH", func(c *proxyConfig) { c.ssh = []string{"user@host:abc"} }},
		{"timeout", func(c *proxyConfig) { c.startupTimeout = 0 }},
		{"interval", func(c *proxyConfig) { c.healthInterval = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.change(&cfg)
			if err := cfg.validate(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyAttachedTunnelDeathUpdatesRules(t *testing.T) {
	first := socksListener(t, [2]byte{5, 0})
	second := socksListener(t, [2]byte{5, 0})
	cfg := testConfig(t)
	cfg.attach = []int{listenerPort(first), listenerPort(second)}
	m := newFakeFirewall()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runProxy(ctx, cfg, io.Discard, newFirewall(cfg.port, m.run)) }()
	waitUpdate(t, m)
	_ = first.Close()
	updated := waitUpdate(t, m)
	if strings.Contains(updated, "127.0.0.1:"+strconv.Itoa(cfg.attach[0])) || strings.Count(updated, "-j DNAT") != 1 {
		t.Fatalf("dead tunnel remained in rules: %s", updated)
	}
	cancel()
	if err := waitProxy(t, done); err != nil {
		t.Fatal(err)
	}
	m.assertClean(t)
	if err := probeSOCKS(context.Background(), cfg.attach[1]); err != nil {
		t.Fatalf("attached tunnel was stopped: %v", err)
	}
}

func TestProxyAllAttachedTunnelsFail(t *testing.T) {
	listener := socksListener(t, [2]byte{5, 0})
	cfg := testConfig(t)
	cfg.attach = []int{listenerPort(listener)}
	m := newFakeFirewall()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runProxy(ctx, cfg, io.Discard, newFirewall(cfg.port, m.run)) }()
	waitUpdate(t, m)
	_ = listener.Close()
	if err := waitProxy(t, done); err == nil || !strings.Contains(err.Error(), "all SOCKS tunnels stopped") {
		t.Fatalf("unexpected result: %v", err)
	}
	m.assertClean(t)
}

func TestProxyFirewallFailureRollsBackAndStopsSSH(t *testing.T) {
	for _, failure := range []string{"restore", "-A"} {
		t.Run(failure, func(t *testing.T) {
			dir := mockSSH(t)
			cfg := testConfig(t)
			cfg.ssh = []string{"ready.test"}
			m := newFakeFirewall()
			m.fail = failure
			err := runProxy(context.Background(), cfg, io.Discard, newFirewall(cfg.port, m.run))
			if err == nil {
				t.Fatal("expected firewall error")
			}
			m.assertClean(t)
			assertChildStopped(t, dir, "ready.test")
		})
	}
}

func TestProxyDoesNotPublishFailedSSH(t *testing.T) {
	mockSSH(t)
	cfg := testConfig(t)
	cfg.ssh = []string{"fail.test"}
	m := newFakeFirewall()
	if err := runProxy(context.Background(), cfg, io.Discard, newFirewall(cfg.port, m.run)); err == nil {
		t.Fatal("expected no working tunnels error")
	}
	if len(m.calls) != 0 {
		t.Fatalf("published failed tunnel: %v", m.calls)
	}
	m.assertClean(t)
}

func TestProxyRejectsNonSOCKSAttachedPort(t *testing.T) {
	listener := socksListener(t, [2]byte{'H', 'T'})
	cfg := testConfig(t)
	cfg.attach = []int{listenerPort(listener)}
	m := newFakeFirewall()
	if err := runProxy(context.Background(), cfg, io.Discard, newFirewall(cfg.port, m.run)); err == nil {
		t.Fatal("accepted non-SOCKS tunnel")
	}
	if len(m.calls) != 0 {
		t.Fatal("changed firewall before validating tunnel")
	}
}

func TestProxyRejectsOccupiedFacade(t *testing.T) {
	listener := socksListener(t, [2]byte{5, 0})
	cfg := testConfig(t)
	cfg.port = listenerPort(listener)
	cfg.ssh = []string{"host"}
	m := newFakeFirewall()
	if err := runProxy(context.Background(), cfg, io.Discard, newFirewall(cfg.port, m.run)); err == nil {
		t.Fatal("accepted an occupied facade port")
	}
	if len(m.calls) != 0 {
		t.Fatal("modified firewall before detecting occupied port")
	}
}

func TestProxySSHExitRemovesDestination(t *testing.T) {
	dir := mockSSH(t)
	cfg := testConfig(t)
	cfg.ssh = []string{"first.test", "second.test"}
	cfg.healthInterval = time.Hour
	m := newFakeFirewall()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runProxy(ctx, cfg, io.Discard, newFirewall(cfg.port, m.run)) }()
	initial := waitUpdate(t, m)
	if strings.Count(initial, "-j DNAT") != 2 {
		t.Fatal(initial)
	}
	data, err := os.ReadFile(filepath.Join(dir, "first.test.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	defer process.Release()
	if err := process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	updated := waitUpdate(t, m)
	if strings.Count(updated, "-j DNAT") != 1 {
		t.Fatalf("failed SSH remained eligible: %s", updated)
	}
	cancel()
	if err := waitProxy(t, done); err != nil {
		t.Fatal(err)
	}
	m.assertClean(t)
	assertChildStopped(t, dir, "first.test")
	assertChildStopped(t, dir, "second.test")
}

func TestProxyCancellationDuringStartup(t *testing.T) {
	dir := mockSSH(t)
	cfg := testConfig(t)
	cfg.ssh = []string{"hang.test"}
	m := newFakeFirewall()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runProxy(ctx, cfg, io.Discard, newFirewall(cfg.port, m.run)) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "hang.test.pid")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SSH did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := waitProxy(t, done); err != nil {
		t.Fatal(err)
	}
	m.assertClean(t)
	assertChildStopped(t, dir, "hang.test")
}

func TestProxyCancellationAfterChainCreationRollsBack(t *testing.T) {
	listener := socksListener(t, [2]byte{5, 0})
	cfg := testConfig(t)
	cfg.attach = []int{listenerPort(listener)}
	m := newFakeFirewall()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner := func(ctx context.Context, program, input string, args ...string) error {
		err := m.run(ctx, program, input, args...)
		if program == "iptables" && len(args) > 4 && args[4] == "-N" && err == nil {
			cancel()
		}
		return err
	}
	if err := runProxy(ctx, cfg, io.Discard, newFirewall(cfg.port, runner)); err != nil {
		t.Fatal(err)
	}
	m.assertClean(t)
}

func TestProxyRuntimeUpdateFailureCleansUp(t *testing.T) {
	first := socksListener(t, [2]byte{5, 0})
	second := socksListener(t, [2]byte{5, 0})
	cfg := testConfig(t)
	cfg.attach = []int{listenerPort(first), listenerPort(second)}
	m := newFakeFirewall()
	restores := 0
	runner := func(ctx context.Context, program, input string, args ...string) error {
		if program == "iptables-restore" {
			restores++
			if restores == 2 {
				return fmt.Errorf("injected runtime update failure")
			}
		}
		return m.run(ctx, program, input, args...)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runProxy(ctx, cfg, io.Discard, newFirewall(cfg.port, runner)) }()
	waitUpdate(t, m)
	_ = first.Close()
	if err := waitProxy(t, done); err == nil || !strings.Contains(err.Error(), "update active tunnels") {
		t.Fatalf("runtime firewall failure lost: %v", err)
	}
	m.assertClean(t)
	if err := probeSOCKS(context.Background(), cfg.attach[1]); err != nil {
		t.Fatalf("external tunnel was stopped: %v", err)
	}
}
