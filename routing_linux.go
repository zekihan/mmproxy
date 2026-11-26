package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Netlink constants missing from package syscall.
const (
	nlmFRequest = 0x1
	nlmFReplace = 0x100
	nlmFExcl    = 0x200
	nlmFCreate  = 0x400
	nlmFAck     = 0x4

	rtaOIF   = 4
	rtaTable = 15

	fraSrc      = 2
	fraIIFName  = 3
	fraPriority = 6
	fraTable    = 15

	frActToTbl = 1

	rtnLocal    = 2
	rtprotBoot  = 3
	rtScopeHost = 254
)

var native = binary.NativeEndian

func align4(n int) int { return (n + 3) &^ 3 }

func attr(typ uint16, data []byte) []byte {
	b := make([]byte, align4(4+len(data)))
	native.PutUint16(b[0:], uint16(4+len(data)))
	native.PutUint16(b[2:], typ)
	copy(b[4:], data)
	return b
}

func attrU32(typ uint16, v uint32) []byte {
	var d [4]byte
	native.PutUint32(d[:], v)
	return attr(typ, d[:])
}

func message(typ, flags uint16, seq uint32, payload []byte) []byte {
	b := make([]byte, syscall.NLMSG_HDRLEN+len(payload))
	native.PutUint32(b[0:], uint32(len(b)))
	native.PutUint16(b[4:], typ)
	native.PutUint16(b[6:], flags)
	native.PutUint32(b[8:], seq)
	copy(b[syscall.NLMSG_HDRLEN:], payload)
	return b
}

func tableByte(table uint32) byte {
	if table < 256 {
		return byte(table)
	}
	return 0
}

// localRouteMessage builds `ip route add local <default> dev <ifindex> table <table>`.
// Existing entries are checked before attempting an exclusive add.
func localRouteMessage(family int, table uint32, ifindex int, seq uint32) []byte {
	scope := byte(0)
	if family == syscall.AF_INET {
		scope = rtScopeHost
	}
	body := []byte{byte(family), 0, 0, 0, tableByte(table), rtprotBoot, scope, rtnLocal, 0, 0, 0, 0}
	body = append(body, attrU32(rtaTable, table)...)
	body = append(body, attrU32(rtaOIF, uint32(ifindex))...)
	return message(syscall.RTM_NEWROUTE, nlmFRequest|nlmFAck|nlmFCreate|nlmFExcl, seq, body)
}

// iifRuleMessage builds `ip rule add from <src>/<srcLen> iif <iif> table <table> priority <prio>`.
// NLM_F_EXCL turns an identical existing rule into EEXIST. An explicit priority is
// required for the kernel's duplicate detection.
func iifRuleMessage(family int, src net.IP, srcLen int, iif string, table, priority uint32, seq uint32) []byte {
	body := []byte{byte(family), 0, byte(srcLen), 0, tableByte(table), 0, 0, frActToTbl, 0, 0, 0, 0}
	body = append(body, attr(fraSrc, src)...)
	body = append(body, attr(fraIIFName, append([]byte(iif), 0))...)
	body = append(body, attrU32(fraPriority, priority)...)
	body = append(body, attrU32(fraTable, table)...)
	return message(syscall.RTM_NEWRULE, nlmFRequest|nlmFAck|nlmFCreate|nlmFExcl, seq, body)
}

// ackError extracts the errno from a netlink acknowledgement; nil means success.
func ackError(resp []byte, seq uint32) error {
	for len(resp) >= syscall.NLMSG_HDRLEN {
		length := int(native.Uint32(resp[0:]))
		if length < syscall.NLMSG_HDRLEN || length > len(resp) {
			return errors.New("malformed netlink response")
		}
		typ := native.Uint16(resp[4:])
		if native.Uint32(resp[8:]) == seq && typ == syscall.NLMSG_ERROR {
			if length < syscall.NLMSG_HDRLEN+4 {
				return errors.New("short netlink error")
			}
			if code := int32(native.Uint32(resp[syscall.NLMSG_HDRLEN:])); code != 0 {
				return syscall.Errno(-code)
			}
			return nil
		}
		if align4(length) > len(resp) {
			return errors.New("malformed netlink response")
		}
		resp = resp[align4(length):]
	}
	return errors.New("no netlink acknowledgement")
}

type conn struct {
	fd  int
	seq uint32
}

func dialNetlink() (*conn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &conn{fd: fd}, nil
}

func (c *conn) close() { syscall.Close(c.fd) }

func (c *conn) do(build func(seq uint32) []byte) error {
	c.seq++
	if err := syscall.Sendto(c.fd, build(c.seq), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	n, _, err := syscall.Recvfrom(c.fd, buf, 0)
	if err != nil {
		return err
	}
	return ackError(buf[:n], c.seq)
}

const (
	envSetup    = "MMPROXY_SETUP_ROUTING"
	envTable    = "MMPROXY_ROUTING_TABLE"
	envPriority = "MMPROXY_ROUTING_PRIORITY"

	defaultTable    = 123
	defaultPriority = 32765
)

type routingConfig struct {
	enabled         bool
	table, priority uint32
}

func parseConfig(getenv func(string) string) (routingConfig, error) {
	cfg := routingConfig{table: defaultTable, priority: defaultPriority}
	if v := getenv(envSetup); v != "" {
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			return cfg, fmt.Errorf("%s: %w", envSetup, err)
		}
		cfg.enabled = enabled
	}
	for _, e := range []struct {
		name string
		dst  *uint32
		min  uint64
		max  uint64
	}{
		// Tables 253-255 are the kernel's default, main and local tables.
		{envTable, &cfg.table, 1, 0xfffffffe},
		{envPriority, &cfg.priority, 1, 32765},
	} {
		v := getenv(e.name)
		if v == "" {
			continue
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n < e.min || n > e.max {
			return cfg, fmt.Errorf("%s: %q is not an integer in %d..%d", e.name, v, e.min, e.max)
		}
		*e.dst = uint32(n)
	}
	if cfg.table >= 253 && cfg.table <= 255 {
		return cfg, fmt.Errorf("%s: table %d is reserved", envTable, cfg.table)
	}
	return cfg, nil
}

func configureRouting(getenv func(string) string) error {
	cfg, err := parseConfig(getenv)
	if err != nil || !cfg.enabled {
		return err
	}
	return applyRouting(cfg.table, cfg.priority)
}

type policyEntry struct {
	family int
	kind   uint16
	create func(uint32) []byte
	match  func([]byte, map[uint16][]byte) (bool, bool)
}

func attributes(body []byte) (map[uint16][]byte, error) {
	result := make(map[uint16][]byte)
	for len(body) > 0 {
		if len(body) < 4 {
			return nil, errors.New("short routing attribute")
		}
		length := int(native.Uint16(body))
		if length < 4 || align4(length) > len(body) {
			return nil, errors.New("invalid routing attribute")
		}
		result[native.Uint16(body[2:])] = body[4:length]
		body = body[align4(length):]
	}
	return result, nil
}

func value32(data []byte, fallback uint32) uint32 {
	if len(data) == 4 {
		return native.Uint32(data)
	}
	return fallback
}

func (entry policyEntry) inspect() (bool, error) {
	query := uint16(syscall.RTM_GETROUTE)
	if entry.kind == syscall.RTM_NEWRULE {
		query = syscall.RTM_GETRULE
	}
	data, err := syscall.NetlinkRIB(int(query), entry.family)
	if err != nil {
		return false, err
	}
	messages, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return false, err
	}
	found := false
	for _, m := range messages {
		if m.Header.Type != entry.kind || len(m.Data) < 12 || int(m.Data[0]) != entry.family {
			continue
		}
		attrs, err := attributes(m.Data[12:])
		if err != nil {
			return false, err
		}
		inScope, exact := entry.match(m.Data[:12], attrs)
		if inScope {
			if !exact || found {
				return false, fmt.Errorf("conflicting policy route or rule for address family %d", entry.family)
			}
			found = true
		}
	}
	return found, nil
}

func applyRouting(table, priority uint32) error {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer c.close()
	disableIPv6, _ := os.ReadFile("/proc/sys/net/ipv6/conf/lo/disable_ipv6")
	var entries []policyEntry
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		if family == syscall.AF_INET6 && strings.TrimSpace(string(disableIPv6)) == "1" {
			continue
		}
		scope := byte(0)
		src := net.IPv6loopback
		prefix := 128
		if family == syscall.AF_INET {
			scope = rtScopeHost
			src = net.IPv4(127, 0, 0, 0).To4()
			prefix = 8
		}
		entries = append(entries, policyEntry{family, syscall.RTM_NEWROUTE,
			func(seq uint32) []byte { return localRouteMessage(family, table, lo.Index, seq) },
			func(body []byte, a map[uint16][]byte) (bool, bool) {
				if value32(a[rtaTable], uint32(body[4])) != table {
					return false, false
				}
				for id := range a {
					switch id {
					case rtaTable, rtaOIF, 1, 6, 12, 20:
					default:
						return true, false
					}
				}
				return true, body[1] == 0 && body[2] == 0 && body[3] == 0 && body[6] == scope &&
					body[7] == rtnLocal && value32(a[rtaOIF], 0) == uint32(lo.Index) && allZero(a[1]) &&
					(value32(a[6], 0) == 0 || family == syscall.AF_INET6 && value32(a[6], 0) == 1024)
			},
		}, policyEntry{family, syscall.RTM_NEWRULE,
			func(seq uint32) []byte { return iifRuleMessage(family, src, prefix, "lo", table, priority, seq) },
			func(body []byte, a map[uint16][]byte) (bool, bool) {
				if value32(a[fraPriority], 0) != priority {
					return false, false
				}
				for id := range a {
					switch id {
					case fraSrc, fraIIFName, fraPriority, fraTable, 21:
					case 14:
						if value32(a[id], 0) != ^uint32(0) {
							return true, false
						}
					default:
						return true, false
					}
				}
				return true, body[1] == 0 && int(body[2]) == prefix && body[3] == 0 && body[7] == frActToTbl &&
					native.Uint32(body[8:]) == 0 && value32(a[fraTable], uint32(body[4])) == table &&
					bytes.Equal(a[fraSrc], src) && string(a[fraIIFName]) == "lo\x00"
			},
		})
	}
	present := make([]bool, len(entries))
	for i, entry := range entries {
		if present[i], err = entry.inspect(); err != nil {
			return err
		}
	}
	for i, entry := range entries {
		if present[i] {
			continue
		}
		err := c.do(entry.create)
		if err != nil && !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("install policy routing entry: %w", err)
		}
		ok, err := entry.inspect()
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("policy routing entry did not match after installation")
		}
	}
	return nil
}

func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
