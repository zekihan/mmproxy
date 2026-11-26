package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

type config struct {
	protocol                              string
	front, back4, back6                   netip.AddrPort
	peers, destinations                   []netip.Prefix
	dynamic, transparent, mixed           bool
	mark, verbose, workers                int
	maxSessions                           int64
	headerTimeout, detectTimeout, udpIdle time.Duration
	version                               bool
}

var version = "dev"

func readPrefixes(path string) ([]netip.Prefix, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var prefixes []netip.Prefix
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		if line = strings.TrimSpace(line); line != "" {
			prefix, err := netip.ParsePrefix(line)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return prefixes, nil
}

func resolveAddress(value string, family int) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return netip.AddrPort{}, err
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	addresses, err := net.LookupIP(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, address := range addresses {
		if addr, ok := netip.AddrFromSlice(address); ok {
			addr = addr.Unmap()
			if family == 0 || family == 4 && addr.Is4() || family == 6 && addr.Is6() {
				return netip.AddrPortFrom(addr, uint16(number)), nil
			}
		}
	}
	return netip.AddrPort{}, errors.New("no address of the requested family")
}

func readConfig(args []string, output io.Writer) (config, error) {
	var cfg config
	var front, v4, v6, allowed, destinations string
	var idle int
	flags := flag.NewFlagSet("mmproxy", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&cfg.protocol, "p", "tcp", "forward tcp or udp")
	flags.StringVar(&front, "l", "0.0.0.0:8443", "listen address")
	flags.StringVar(&v4, "4", "127.0.0.1:443", "IPv4 backend")
	flags.StringVar(&v6, "6", "[::1]:443", "IPv6 backend")
	flags.StringVar(&allowed, "allowed-subnets", "", "file of trusted peer CIDRs")
	flags.StringVar(&destinations, "allowed-destinations", "", "optional file of permitted dynamic destination CIDRs")
	flags.BoolVar(&cfg.dynamic, "dynamic-destination", false, "use the destination in the PROXY header")
	flags.BoolVar(&cfg.transparent, "listen-transparent", false, "use a transparent listener socket")
	flags.BoolVar(&cfg.mixed, "allow-raw-tcp", false, "accept raw TCP from explicitly trusted peers")
	flags.IntVar(&cfg.mark, "mark", 0, "mark for outgoing transparent sockets")
	flags.IntVar(&cfg.verbose, "v", 0, "connection verbosity (0–2)")
	flags.IntVar(&cfg.workers, "listeners", 1, "number of listener sockets")
	flags.IntVar(&idle, "close-after", 60, "UDP idle timeout in seconds")
	flags.Int64Var(&cfg.maxSessions, "max-connections", 0, "lower the derived session cap")
	flags.DurationVar(&cfg.headerTimeout, "header-timeout", time.Second, "PROXY header deadline")
	flags.DurationVar(&cfg.detectTimeout, "raw-detection-timeout", 200*time.Millisecond, "wait for a PROXY prefix before using raw TCP")
	flags.BoolVar(&cfg.version, "version", false, "print the version")
	if err := flags.Parse(args); err != nil {
		return cfg, err
	}
	if cfg.version {
		return cfg, nil
	}
	if flags.NArg() != 0 {
		return cfg, errors.New("unexpected positional argument")
	}
	if cfg.protocol != "tcp" && cfg.protocol != "udp" {
		return cfg, errors.New("-p must be tcp or udp")
	}
	if cfg.mark < 0 || uint64(cfg.mark) > 1<<32-1 || cfg.verbose < 0 || cfg.verbose > 2 || cfg.workers < 1 ||
		idle < 0 || uint64(idle) > uint64((1<<63-1)/time.Second) || cfg.maxSessions < 0 ||
		cfg.headerTimeout <= 0 || cfg.detectTimeout <= 0 || (cfg.mixed && cfg.detectTimeout > cfg.headerTimeout) {
		return cfg, errors.New("invalid mark, verbosity, listener count, limit or timeout")
	}
	var err error
	if cfg.front, err = resolveAddress(front, 0); err != nil {
		return cfg, fmt.Errorf("-l: %w", err)
	}
	if cfg.back4, err = resolveAddress(v4, 4); err != nil {
		return cfg, fmt.Errorf("-4: %w", err)
	}
	if cfg.back6, err = resolveAddress(v6, 6); err != nil {
		return cfg, fmt.Errorf("-6: %w", err)
	}
	if cfg.peers, err = readPrefixes(allowed); err != nil {
		return cfg, err
	}
	if cfg.destinations, err = readPrefixes(destinations); err != nil {
		return cfg, err
	}
	if destinations != "" && len(cfg.destinations) == 0 {
		return cfg, fmt.Errorf("empty destination allowlist: %s", destinations)
	}
	if cfg.mixed && (cfg.protocol != "tcp" || len(cfg.peers) == 0) {
		return cfg, errors.New("-allow-raw-tcp needs a nonempty -allowed-subnets file and TCP")
	}
	cfg.udpIdle = time.Duration(idle) * time.Second
	return cfg, nil
}

func permitted(list []netip.Prefix, addr netip.Addr) bool {
	if len(list) == 0 {
		return true
	}
	for _, prefix := range list {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (cfg config) target(peer, source, destination netip.AddrPort) (netip.AddrPort, error) {
	if cfg.dynamic && source.IsValid() && destination.IsValid() {
		if !permitted(cfg.destinations, destination.Addr()) {
			return netip.AddrPort{}, errors.New("dynamic destination denied")
		}
		return destination, nil
	}
	if !source.IsValid() {
		source = peer
	}
	if source.Addr().Unmap().Is4() {
		return cfg.back4, nil
	}
	return cfg.back6, nil
}

type limits struct {
	fdUsed, sessions  atomic.Int64
	fdMax, sessionMax int64
}

func newLimits(cfg config) (*limits, error) {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return nil, err
	}
	maximum := int64(min(limit.Cur, uint64(1<<31-1))) - int64(cfg.workers)*2 - 32
	if maximum < 2 {
		return nil, errors.New("descriptor limit is too low for configured listeners")
	}
	sessions := maximum / 2
	if cfg.maxSessions > 0 {
		sessions = min(sessions, cfg.maxSessions)
	}
	return &limits{fdMax: maximum, sessionMax: sessions}, nil
}

func reserve(counter *atomic.Int64, amount, maximum int64) bool {
	for current := counter.Load(); current <= maximum-amount; current = counter.Load() {
		if counter.CompareAndSwap(current, current+amount) {
			return true
		}
	}
	return false
}

func (l *limits) admit(fd int64) bool {
	if !reserve(&l.sessions, 1, l.sessionMax) {
		return false
	}
	if !reserve(&l.fdUsed, fd, l.fdMax) {
		l.sessions.Add(-1)
		return false
	}
	return true
}

func (l *limits) depart(fd int64) {
	l.fdUsed.Add(-fd)
	l.sessions.Add(-1)
}
