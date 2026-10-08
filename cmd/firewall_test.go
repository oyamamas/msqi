package cmd

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// Model rule identity, ownership, and atomic restore commits independently of
// the command builder. No test in this file invokes the system firewall.
type fakeFirewall struct {
	mu      sync.Mutex
	chains  map[string][]string
	jumps   []string
	calls   []string
	fail    string
	updates chan string
}

func newFakeFirewall() *fakeFirewall {
	return &fakeFirewall{chains: map[string][]string{"FOREIGN": {"keep me"}}, updates: make(chan string, 16)}
}

func (m *fakeFirewall) run(ctx context.Context, program, input string, args ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	m.calls = append(m.calls, program+" "+strings.Join(args, " "))
	if program == "iptables-restore" {
		if m.fail == "restore" {
			return errors.New("injected restore failure")
		}
		if !reflect.DeepEqual(args, []string{"--wait", "5", "--noflush"}) {
			return fmt.Errorf("unsafe restore arguments %v", args)
		}
		lines := strings.Split(strings.TrimSpace(input), "\n")
		if lines[0] != "*nat" || lines[len(lines)-1] != "COMMIT" {
			return errors.New("invalid restore transaction")
		}
		flush := strings.Fields(lines[1])
		if len(flush) != 2 || flush[0] != "-F" {
			return errors.New("missing explicit owned-chain flush")
		}
		chain := flush[1]
		if _, exists := m.chains[chain]; !exists {
			return errors.New("unknown chain")
		}
		var rules []string
		for _, line := range lines[2 : len(lines)-1] {
			if !strings.HasPrefix(line, "-A "+chain+" ") {
				return errors.New("restore touched another chain")
			}
			rules = append(rules, line)
		}
		m.chains[chain] = rules
		m.updates <- input
		return nil
	}
	if program != "iptables" || len(args) < 6 || !reflect.DeepEqual(args[:4], []string{"-w", "5", "-t", "nat"}) {
		return fmt.Errorf("unexpected command %s %v", program, args)
	}
	a := args[4:]
	action, chain := a[0], a[1]
	if m.fail == action {
		return fmt.Errorf("injected %s failure", action)
	}
	switch action {
	case "-N":
		if _, exists := m.chains[chain]; exists {
			return errors.New("chain already exists")
		}
		m.chains[chain] = nil
	case "-S":
		if _, exists := m.chains[chain]; !exists {
			return errors.New("chain does not exist")
		}
	case "-A":
		if chain != "OUTPUT" || len(m.chains[a[len(a)-1]]) == 0 {
			return errors.New("published an unready chain")
		}
		m.jumps = append(m.jumps, strings.Join(a[1:], " "))
	case "-D":
		needle := strings.Join(a[1:], " ")
		for i, jump := range m.jumps {
			if jump == needle {
				m.jumps = append(m.jumps[:i], m.jumps[i+1:]...)
				return nil
			}
		}
		return errors.New("exact jump rule not found")
	case "-F":
		if _, exists := m.chains[chain]; !exists {
			return errors.New("chain does not exist")
		}
		m.chains[chain] = nil
	case "-X":
		for _, jump := range m.jumps {
			if strings.HasSuffix(jump, "-j "+chain) {
				return errors.New("chain still referenced")
			}
		}
		if len(m.chains[chain]) > 0 {
			return errors.New("chain not empty")
		}
		delete(m.chains, chain)
	default:
		return fmt.Errorf("unexpected action %s", action)
	}
	return nil
}

func (m *fakeFirewall) assertClean(t *testing.T) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !reflect.DeepEqual(m.chains, map[string][]string{"FOREIGN": {"keep me"}}) || len(m.jumps) != 0 {
		t.Fatalf("firewall resources leaked or foreign chain changed: chains=%v jumps=%v", m.chains, m.jumps)
	}
}

func TestFirewallInstallUpdateCleanup(t *testing.T) {
	m := newFakeFirewall()
	f := newFirewall(1337, m.run)
	if err := f.install(context.Background(), []int{1444, 1555}); err != nil {
		t.Fatal(err)
	}
	initial := <-m.updates
	if !strings.Contains(initial, "--every 2 --packet 0") || strings.Count(initial, "-j DNAT") != 2 {
		t.Fatalf("incorrect balancing: %s", initial)
	}
	if err := f.replace(context.Background(), []int{1555}); err != nil {
		t.Fatal(err)
	}
	updated := <-m.updates
	if strings.Contains(updated, "1444") || strings.Contains(updated, "statistic") || strings.Count(updated, "-j DNAT") != 1 {
		t.Fatalf("failed tunnel still eligible: %s", updated)
	}
	if err := f.close(); err != nil {
		t.Fatal(err)
	}
	if err := f.close(); err != nil {
		t.Fatal(err)
	}
	m.assertClean(t)
}

func TestFirewallCollisionDoesNotAdoptExistingChain(t *testing.T) {
	m := newFakeFirewall()
	f := newFirewall(1337, m.run)
	attempt := 0
	f.chainName = func() (string, error) {
		attempt++
		if attempt == 1 {
			return "FOREIGN", nil
		}
		return "MSQIfresh", nil
	}
	if err := f.install(context.Background(), []int{1444}); err != nil {
		t.Fatal(err)
	}
	if f.chain != "MSQIfresh" {
		t.Fatalf("adopted chain %s", f.chain)
	}
	if err := f.close(); err != nil {
		t.Fatal(err)
	}
	m.assertClean(t)
}

func TestFirewallCreationFailureDoesNotCleanUnownedChain(t *testing.T) {
	m := newFakeFirewall()
	m.fail = "-N"
	f := newFirewall(1337, m.run)
	if err := f.install(context.Background(), []int{1444}); err == nil {
		t.Fatal("expected creation error")
	}
	if err := f.close(); err != nil {
		t.Fatal(err)
	}
	m.assertClean(t)
	for _, call := range m.calls {
		if strings.Contains(call, " -F ") || strings.Contains(call, " -X ") || strings.Contains(call, " -A ") {
			t.Fatalf("mutated unowned chain: %s", call)
		}
	}
}

func TestFirewallCollisionExhaustion(t *testing.T) {
	m := newFakeFirewall()
	f := newFirewall(1337, m.run)
	f.chainName = func() (string, error) { return "FOREIGN", nil }
	if err := f.install(context.Background(), []int{1444}); err == nil {
		t.Fatal("expected collision error")
	}
	if err := f.close(); err != nil {
		t.Fatal(err)
	}
	m.assertClean(t)
}

func TestFirewallRestoreFailurePreservesActiveRules(t *testing.T) {
	m := newFakeFirewall()
	f := newFirewall(1337, m.run)
	if err := f.install(context.Background(), []int{1444}); err != nil {
		t.Fatal(err)
	}
	before := append([]string(nil), m.chains[f.chain]...)
	m.fail = "restore"
	if err := f.replace(context.Background(), []int{1555}); err == nil {
		t.Fatal("expected restore failure")
	}
	if !reflect.DeepEqual(before, m.chains[f.chain]) {
		t.Fatal("failed restore changed active rules")
	}
	if err := f.close(); err != nil {
		t.Fatal(err)
	}
	m.assertClean(t)
}

func TestFirewallReportsCleanupFailure(t *testing.T) {
	m := newFakeFirewall()
	f := newFirewall(1337, m.run)
	if err := f.install(context.Background(), []int{1444}); err != nil {
		t.Fatal(err)
	}
	m.fail = "-D"
	if err := f.close(); err == nil || !strings.Contains(err.Error(), "remove OUTPUT jump") {
		t.Fatalf("cleanup error lost: %v", err)
	}
	m.fail = ""
	if err := f.close(); err != nil {
		t.Fatal(err)
	}
	m.assertClean(t)
}
