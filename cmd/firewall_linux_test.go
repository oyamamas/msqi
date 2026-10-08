//go:build linux

package cmd

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This opt-in test must run in a separate network namespace. The CI job uses
// unshare --net, so even real iptables commands cannot change the host's rules.
func TestLinuxFirewallIntegration(t *testing.T) {
	if os.Getenv("MSQI_IPTABLES_TEST") != "1" {
		t.Skip("set MSQI_IPTABLES_TEST=1 inside an isolated Linux network namespace")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if self == host {
		t.Fatal("refusing to change firewall in PID 1's network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("integration test needs root in its isolated network namespace")
	}

	backend := func(tag byte) net.Listener {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				_, _ = conn.Write([]byte{tag})
				_ = conn.Close()
			}
		}()
		return listener
	}
	first, second, facade := backend('A'), backend('B'), backend('F')
	f := newFirewall(listenerPort(facade), runCommand)
	t.Cleanup(func() {
		if err := f.close(); err != nil {
			t.Error(err)
		}
	})

	// An unrelated chain is a sentinel against accidental whole-table flushes.
	foreign, err := f.chainName()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.iptables(context.Background(), "-N", foreign); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = f.iptables(context.Background(), "-F", foreign)
		_ = f.iptables(context.Background(), "-X", foreign)
	})
	if err := f.iptables(context.Background(), "-A", foreign, "-j", "RETURN"); err != nil {
		t.Fatal(err)
	}
	readChain := func(chain string) string {
		out, err := exec.Command("iptables", "-w", "5", "-t", "nat", "-S", chain).CombinedOutput()
		if err != nil {
			t.Fatalf("read chain: %v: %s", err, out)
		}
		return string(out)
	}
	foreignBefore := readChain(foreign)
	if err := f.install(context.Background(), []int{listenerPort(first), listenerPort(second)}); err != nil {
		t.Fatal(err)
	}
	dial := func() byte {
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(f.port)), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			t.Fatal(err)
		}
		return b[0]
	}
	counts := map[byte]int{}
	for i := 0; i < 6; i++ {
		counts[dial()]++
	}
	if counts['A'] != 3 || counts['B'] != 3 || counts['F'] != 0 {
		t.Fatalf("round robin failed: %v", counts)
	}

	// A rejected transaction must leave the active DNAT rules intact.
	before := readChain(f.chain)
	f.run = func(ctx context.Context, program, input string, args ...string) error {
		if program == "iptables-restore" {
			input = strings.Replace(input, "COMMIT\n", "-A "+f.chain+" --invalid-msqi-option\nCOMMIT\n", 1)
		}
		return runCommand(ctx, program, input, args...)
	}
	if err := f.replace(context.Background(), []int{listenerPort(second)}); err == nil {
		t.Fatal("invalid transaction unexpectedly succeeded")
	}
	if after := readChain(f.chain); after != before {
		t.Fatalf("failed transaction changed rules:\nbefore %s\nafter %s", before, after)
	}
	f.run = runCommand
	if err := f.replace(context.Background(), []int{listenerPort(second)}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if tag := dial(); tag != 'B' {
			t.Fatalf("removed backend received traffic: %c", tag)
		}
	}
	if err := f.close(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("iptables", "-t", "nat", "-S", f.chain).Run(); err == nil {
		t.Fatal("owned chain was left behind")
	}
	if tag := dial(); tag != 'F' {
		t.Fatalf("OUTPUT jump was left behind: %c", tag)
	}
	if after := readChain(foreign); after != foreignBefore {
		t.Fatalf("unrelated chain was changed: %s", after)
	}
}
