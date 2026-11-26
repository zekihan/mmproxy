//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func binaryHeader(source, destination netip.AddrPort, transport byte) []byte {
	v4 := source.Addr().Is4()
	family := byte(0x20)
	if v4 {
		family = 0x10
	}
	body := append(source.Addr().AsSlice(), destination.Addr().AsSlice()...)
	body = binary.BigEndian.AppendUint16(body, source.Port())
	body = binary.BigEndian.AppendUint16(body, destination.Port())
	head := append(bytes.Clone(signature), 0x21, family|transport, 0, byte(len(body)))
	return append(head, body...)
}

func TestWireHeaders(t *testing.T) {
	for _, tc := range []struct {
		wire      string
		transport byte
		reject    bool
		source    string
	}{
		{"PROXY TCP4 192.0.2.1 192.0.2.2 12345 22\r\n", 1, false, "192.0.2.1:12345"},
		{"PROXY TCP6 2001:db8::1 2001:db8::2 12345 22\r\n", 1, false, "[2001:db8::1]:12345"},
		{"PROXY UNKNOWN\r\n", 1, false, ""},
		{"PROXY TCP4 2001:db8::1 192.0.2.2 12345 22\r\n", 1, true, ""},
		{"PROXY TCP4 192.0.2.1 192.0.2.2 0123 22\r\n", 1, true, ""},
		{"PROXY TCP4 192.0.2.1 192.0.2.2 12345 22\r\n", 2, true, ""},
		{"PROXYBAD UNKNOWN\r\n", 1, true, ""},
	} {
		result, n := parseHeader([]byte(tc.wire), tc.transport)
		if tc.reject {
			if n >= 0 {
				t.Fatalf("accepted %q", tc.wire)
			}
			continue
		}
		if n != len(tc.wire) {
			t.Fatalf("header offset for %q = %d", tc.wire, n)
		}
		if tc.source == "" {
			if result.source.IsValid() {
				t.Fatal(result.source)
			}
		} else if result.source.String() != tc.source {
			t.Fatal(result.source)
		}
	}
	for _, transport := range []byte{1, 2} {
		src := netip.MustParseAddrPort("[2001:db8::8]:5000")
		dst := netip.MustParseAddrPort("[2001:db8::9]:22")
		header := binaryHeader(src, dst, transport)
		for i := range header {
			if _, n := parseHeader(header[:i], transport); n != 0 {
				t.Fatalf("truncated offset %d = %d", i, n)
			}
		}
		result, n := parseHeader(header, transport)
		if n != len(header) || result.source != src || result.destination != dst {
			t.Fatal(result, n)
		}
		header[12] = 0x20
		result, n = parseHeader(header, transport)
		if n != len(header) || result.source.IsValid() {
			t.Fatal(result, n)
		}
	}
}

func TestMixedAndBudget(t *testing.T) {
	if _, err := readConfig([]string{"-allow-raw-tcp"}, io.Discard); err == nil {
		t.Fatal("raw without explicit allowlist")
	}
	path := filepath.Join(t.TempDir(), "allowed")
	if err := os.WriteFile(path, []byte("127.0.0.1/32\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := readConfig([]string{"-allow-raw-tcp", "-allowed-subnets", path}, io.Discard)
	if err != nil || !cfg.mixed {
		t.Fatal(cfg, err)
	}
	if !headerCandidate([]byte("P")) || !headerCandidate([]byte("\r\n")) || headerCandidate([]byte("SSH-2.0")) {
		t.Fatal("detection")
	}
	var l limits
	l.sessionMax, l.fdMax = 4, 4
	if !l.admit(2) || !l.admit(2) || l.admit(1) {
		t.Fatal("overcommitted budget")
	}
	l.depart(2)
	if !l.admit(1) {
		t.Fatal("released capacity was lost")
	}
}

func runProxy(t *testing.T, protocol string, cfg config, executable string, extra ...string) netip.AddrPort {
	t.Helper()
	var front netip.AddrPort
	if protocol == "tcp" {
		socket, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		front = socket.Addr().(*net.TCPAddr).AddrPort()
		socket.Close()
	} else {
		socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		front = socket.LocalAddr().(*net.UDPAddr).AddrPort()
		socket.Close()
	}
	args := append([]string{"-p", protocol, "-l", front.String(), "-4", cfg.back4.String(), "-6", cfg.back6.String(), "-listeners", "2", "-mark", "123", "-close-after", "1", "-v", "1"}, extra...)
	command := exec.Command(executable, args...)
	output := filepath.Join(t.TempDir(), "proxy.log")
	log, err := os.Create(output)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		if err := command.Wait(); err != nil && command.ProcessState == nil {
			t.Log(err)
		}
		if t.Failed() {
			if data, err := os.ReadFile(output); err == nil {
				t.Logf("proxy output: %s", data)
			}
		}
	})
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		if data, _ := os.ReadFile(output); bytes.Contains(data, []byte("listening")) {
			return front
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("proxy did not start")
	return front
}

func TestNamespaceCompatibility(t *testing.T) {
	if os.Getenv("MMPROXY_TEST_NETNS") != "1" {
		t.Skip("requires isolated user and network namespaces")
	}
	if err := applyRouting(123, 32765); err != nil {
		t.Fatal(err)
	}
	if err := applyRouting(123, 32765); err != nil {
		t.Fatal(err)
	}
	execPath := os.Getenv("MMPROXY_TEST_BINARY")
	if execPath == "" {
		t.Fatal("MMPROXY_TEST_BINARY not set")
	}
	loop4 := netip.MustParseAddrPort("127.0.0.1:0")
	loop6 := netip.MustParseAddrPort("[::1]:0")
	candidates := map[string]string{"first-party": execPath}
	if stock := os.Getenv("MMPROXY_TEST_UPSTREAM"); stock != "" {
		candidates["upstream"] = stock
	}
	for name, exe := range candidates {
		t.Run(name+"/tcp", func(t *testing.T) {
			v4, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(loop4))
			if err != nil {
				t.Fatal(err)
			}
			defer v4.Close()
			v6, err := net.ListenTCP("tcp6", net.TCPAddrFromAddrPort(loop6))
			if err != nil {
				t.Fatal(err)
			}
			defer v6.Close()
			cfg := config{back4: v4.Addr().(*net.TCPAddr).AddrPort(), back6: v6.Addr().(*net.TCPAddr).AddrPort()}
			front := runProxy(t, "tcp", cfg, exe)
			for i := 0; i < 2; i++ {
				if i == 1 && name == "upstream" {
					continue
				}
				source, target, backend := netip.MustParseAddrPort("192.0.2.8:31500"), cfg.back4, v4
				if i == 1 {
					source, target, backend = netip.MustParseAddrPort("[2001:db8::8]:31500"), cfg.back6, v6
				}
				if name == "upstream" {
					source = netip.MustParseAddrPort("192.0.2.9:31500")
				}
				client, err := net.DialTCP("tcp4", nil, net.TCPAddrFromAddrPort(front))
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				_ = client.SetDeadline(time.Now().Add(3 * time.Second))
				_ = backend.SetDeadline(time.Now().Add(3 * time.Second))
				header := binaryHeader(source, target, 1)
				if name == "first-party" {
					if _, err := client.Write(header[:4]); err != nil {
						t.Fatal(err)
					}
					time.Sleep(5 * time.Millisecond)
					header = header[4:]
				}
				if _, err := client.Write(append(header, []byte("payload")...)); err != nil {
					t.Fatal(err)
				}
				server, err := backend.AcceptTCP()
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(3 * time.Second))
				if server.RemoteAddr().(*net.TCPAddr).AddrPort() != source {
					t.Fatal(server.RemoteAddr(), source)
				}
				_ = client.CloseWrite()
				if data, err := io.ReadAll(server); err != nil || string(data) != "payload" {
					t.Fatal(string(data), err)
				}
				if _, err := server.Write([]byte("reply")); err != nil {
					t.Fatal(err)
				}
				_ = server.CloseWrite()
				if data, err := io.ReadAll(client); err != nil || string(data) != "reply" {
					t.Fatal(string(data), err)
				}
			}
		})
		t.Run(name+"/udp", func(t *testing.T) {
			server, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(loop4))
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			cfg := config{back4: server.LocalAddr().(*net.UDPAddr).AddrPort(), back6: netip.MustParseAddrPort("[::1]:22")}
			front := runProxy(t, "udp", cfg, exe)
			client, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(front))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			source := netip.MustParseAddrPort("192.0.2.8:31501")
			if _, err := client.Write(append(binaryHeader(source, cfg.back4, 2), []byte("ping")...)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 16)
			n, peer, err := server.ReadFromUDPAddrPort(buf)
			if err != nil || string(buf[:n]) != "ping" || peer != source {
				t.Fatal(string(buf[:n]), peer, err)
			}
			if _, err := server.WriteToUDPAddrPort([]byte("pong"), peer); err != nil {
				t.Fatal(err)
			}
			n, err = client.Read(buf)
			if err != nil || string(buf[:n]) != "pong" {
				t.Fatal(string(buf[:n]), err)
			}
		})
	}
	t.Run("namespace routing conflicts", func(t *testing.T) {
		output, err := exec.Command("ip", "-4", "rule", "add", "from", "198.51.100.0/24", "lookup", "123", "priority", "32765").CombinedOutput()
		if err != nil {
			t.Fatal(fmt.Sprintf("%s: %s", err, output))
		}
		if err := applyRouting(123, 32765); err == nil {
			t.Fatal("accepted conflicting rule")
		}
	})
}

func TestBufferedRelayOnPipePressure(t *testing.T) {
	a, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range append(a[:], b[:]...) {
		defer syscall.Close(fd)
	}
	w := worker{limits: &limits{}}
	flow := direction{pipe: pipe{-1, -1}}
	if _, err := syscall.Write(a[0], []byte("buffered")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.pump(&flow, a[1], b[0]); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := syscall.Read(b[1], buf)
	if err != nil || string(buf[:n]) != "buffered" {
		t.Fatal(n, err)
	}
	_, err = syscall.Read(b[1], buf)
	if !errors.Is(err, syscall.EAGAIN) {
		t.Fatal(err)
	}
}
