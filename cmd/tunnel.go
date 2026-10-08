package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type tunnel struct {
	port    int
	cmd     *exec.Cmd // nil for externally managed --attach tunnels
	done    chan struct{}
	waitErr error // only read after done has closed
}

// A zero port preserves a port configured in ~/.ssh/config.
func parseSSHConnectionString(value string) (string, int, error) {
	invalid := func() (string, int, error) {
		return "", 0, fmt.Errorf("invalid SSH destination %q; expected [user@]host[:port] or [user@][IPv6]:port", value)
	}
	if value == "" || strings.ContainsAny(value, " \t\r\n\x00") || strings.Count(value, "@") > 1 {
		return invalid()
	}
	user, host := "", value
	if at := strings.IndexByte(value, '@'); at >= 0 {
		if at == 0 {
			return invalid()
		}
		user, host = value[:at+1], value[at+1:]
	}
	if strings.HasPrefix(value, "-") || host == "" || strings.HasPrefix(host, "-") {
		return invalid()
	}
	port := 0
	switch {
	case strings.HasPrefix(host, "["):
		end := strings.IndexByte(host, ']')
		if end < 0 || net.ParseIP(host[1:end]) == nil {
			return invalid()
		}
		suffix := host[end+1:]
		host = host[1:end]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") {
				return invalid()
			}
			var err error
			port, err = strconv.Atoi(suffix[1:])
			if err != nil || !validPort(port) {
				return invalid()
			}
		}
	case strings.Count(host, ":") == 1:
		var portText string
		host, portText, _ = strings.Cut(host, ":")
		var err error
		port, err = strconv.Atoi(portText)
		if err != nil || !validPort(port) {
			return invalid()
		}
	case strings.Contains(host, ":"):
		if net.ParseIP(host) == nil {
			return invalid()
		}
	}
	if host == "" || strings.ContainsAny(host, "[]/") {
		return invalid()
	}
	return user + host, port, nil
}

func allocateTunnelPort(reserved map[int]bool) (int, error) {
	for attempt := 0; attempt < 100; attempt++ {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return 0, err
		}
		port := listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()
		if !reserved[port] {
			return port, nil
		}
	}
	return 0, fmt.Errorf("could not allocate an unused SSH SOCKS port")
}

func startSSHTunnel(ctx context.Context, destination string, timeout time.Duration, reserved map[int]bool, output io.Writer) (*tunnel, error) {
	address, sshPort, err := parseSSHConnectionString(destination)
	if err != nil {
		return nil, err
	}
	port, err := allocateTunnelPort(reserved)
	if err != nil {
		return nil, fmt.Errorf("allocate SOCKS port: %w", err)
	}
	args := []string{
		"-D", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), "-N", "-T",
		"-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
		"-o", "ExitOnForwardFailure=yes", "-o", "StrictHostKeyChecking=accept-new",
		"-o", "GatewayPorts=no", "-o", "ControlMaster=no", "-o", "ControlPath=none",
		"-o", "ForkAfterAuthentication=no",
	}
	if sshPort != 0 {
		args = append(args, "-p", strconv.Itoa(sshPort))
	}
	args = append(args, address)
	tun := &tunnel{port: port, cmd: exec.Command("ssh", args...), done: make(chan struct{})}
	tun.cmd.Stderr = output
	if err := tun.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start SSH to %s: %w", destination, err)
	}
	go func() {
		tun.waitErr = tun.cmd.Wait()
		close(tun.done)
	}()
	readyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := tun.waitReady(readyCtx); err != nil {
		return nil, errors.Join(fmt.Errorf("SSH to %s: %w", destination, err), tun.close())
	}
	return tun, nil
}

func (t *tunnel) exited() bool {
	select {
	case <-t.done:
		return true
	default:
		return false
	}
}

func (t *tunnel) exitError() error {
	if t.exited() && t.waitErr != nil {
		return fmt.Errorf("SSH on port %d exited: %w", t.port, t.waitErr)
	}
	return fmt.Errorf("SSH on port %d exited", t.port)
}

func (t *tunnel) waitReady(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		if t.exited() {
			return t.exitError()
		}
		if ctx.Err() != nil {
			return fmt.Errorf("waiting for SOCKS readiness: %w", errors.Join(ctx.Err(), lastErr))
		}
		lastErr = probeSOCKS(ctx, t.port)
		if lastErr == nil && !t.exited() {
			return nil
		}
		select {
		case <-t.done:
			return t.exitError()
		case <-ctx.Done():
			return fmt.Errorf("waiting for SOCKS readiness: %w", errors.Join(ctx.Err(), lastErr))
		case <-ticker.C:
		}
	}
}

func probeSOCKS(ctx context.Context, port int) error {
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	// Cancellation must also interrupt a connected peer that never replies.
	stop := context.AfterFunc(probeCtx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := probeCtx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var response [2]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if response != [2]byte{5, 0} {
		return fmt.Errorf("listener is not a SOCKS5 proxy supporting no-authentication")
	}
	return nil
}

func (t *tunnel) close() error {
	if t.cmd == nil || t.cmd.Process == nil || t.exited() {
		return nil
	}
	if err := t.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("stop SSH on port %d: %w", t.port, err)
	}
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case <-t.done:
		return nil
	case <-timer.C:
	}
	if err := t.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("kill SSH on port %d: %w", t.port, err)
	}
	select {
	case <-t.done:
		return nil
	case <-time.After(time.Second):
		return fmt.Errorf("SSH on port %d did not exit after SIGKILL", t.port)
	}
}
