package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type commandRunner func(ctx context.Context, program, input string, args ...string) error

func runCommand(ctx context.Context, program, input string, args ...string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Finish an in-flight mutation before handling a shutdown signal so its
	// successful result is recorded and cleanup knows which resources we own.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", program, strings.Join(args, " "), errors.Join(err, ctx.Err()), strings.TrimSpace(string(output)))
	}
	return nil
}

type firewall struct {
	port      int
	chain     string
	created   bool
	linked    bool
	run       commandRunner
	chainName func() (string, error)
}

func newFirewall(port int, run commandRunner) *firewall {
	return &firewall{port: port, run: run, chainName: func() (string, error) {
		var id [8]byte
		if _, err := rand.Read(id[:]); err != nil {
			return "", err
		}
		return "MSQI" + hex.EncodeToString(id[:]), nil
	}}
}

func (f *firewall) iptables(ctx context.Context, args ...string) error {
	return f.run(ctx, "iptables", "", append([]string{"-w", "5", "-t", "nat"}, args...)...)
}

func (f *firewall) jump(action string) []string {
	return []string{action, "OUTPUT", "-d", "127.0.0.1", "-o", "lo", "-p", "tcp",
		"--dport", strconv.Itoa(f.port), "-j", f.chain}
}

func (f *firewall) install(ctx context.Context, ports []int) error {
	for attempt := 0; attempt < 5; attempt++ {
		name, err := f.chainName()
		if err != nil {
			return fmt.Errorf("generate firewall chain name: %w", err)
		}
		if err := f.iptables(ctx, "-N", name); err != nil {
			// Only retry confirmed name collisions. Never adopt an existing chain.
			if ctx.Err() == nil && f.iptables(ctx, "-S", name) == nil {
				continue
			}
			return fmt.Errorf("create firewall chain: %w", err)
		}
		f.chain, f.created = name, true
		break
	}
	if !f.created {
		return fmt.Errorf("could not allocate a unique firewall chain")
	}
	// Publish the OUTPUT jump only after all destination rules are ready.
	if err := f.replace(ctx, ports); err != nil {
		return err
	}
	if err := f.iptables(ctx, f.jump("-A")...); err != nil {
		return fmt.Errorf("install OUTPUT jump: %w", err)
	}
	f.linked = true
	return nil
}

func (f *firewall) replace(ctx context.Context, ports []int) error {
	if !f.created || len(ports) == 0 {
		return fmt.Errorf("cannot configure an unowned chain or an empty tunnel list")
	}
	var rules strings.Builder
	fmt.Fprintf(&rules, "*nat\n-F %s\n", f.chain)
	for i, port := range ports {
		if !validPort(port) || port == f.port {
			return fmt.Errorf("invalid tunnel port %d", port)
		}
		fmt.Fprintf(&rules, "-A %s -d 127.0.0.1 -o lo -p tcp --dport %d", f.chain, f.port)
		if i < len(ports)-1 {
			fmt.Fprintf(&rules, " -m statistic --mode nth --every %d --packet 0", len(ports)-i)
		}
		fmt.Fprintf(&rules, " -j DNAT --to-destination 127.0.0.1:%d\n", port)
	}
	rules.WriteString("COMMIT\n")
	// --noflush preserves other chains. A single commit replaces our rules
	// without exposing a partially populated chain to new connections.
	if err := f.run(ctx, "iptables-restore", rules.String(), "--wait", "5", "--noflush"); err != nil {
		return fmt.Errorf("configure firewall chain %s: %w", f.chain, err)
	}
	return nil
}

func (f *firewall) close() error {
	if !f.created {
		return nil
	}
	var errs []error
	if f.linked {
		if err := f.iptables(context.Background(), f.jump("-D")...); err != nil {
			errs = append(errs, fmt.Errorf("remove OUTPUT jump: %w", err))
		} else {
			f.linked = false
		}
	}
	if err := f.iptables(context.Background(), "-F", f.chain); err != nil {
		errs = append(errs, fmt.Errorf("flush owned chain: %w", err))
	}
	if err := f.iptables(context.Background(), "-X", f.chain); err != nil {
		errs = append(errs, fmt.Errorf("delete owned chain: %w", err))
	} else {
		f.created = false
	}
	return errors.Join(errs...)
}
