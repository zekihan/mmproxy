package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
)

var signature = []byte("\r\n\r\n\x00\r\nQUIT\n")
var textSignature = []byte("PROXY")

const maxHeader = 16 + 65535

type headerAddresses struct{ source, destination netip.AddrPort }

func port(text string) (uint16, bool) {
	n, err := strconv.ParseUint(text, 10, 16)
	return uint16(n), err == nil && strconv.FormatUint(n, 10) == text
}

func textAddresses(data []byte) (headerAddresses, bool) {
	fields := strings.Split(string(data), " ")
	if len(fields) < 2 || fields[0] != "PROXY" {
		return headerAddresses{}, false
	}
	if fields[1] == "UNKNOWN" {
		return headerAddresses{}, true
	}
	if len(fields) != 6 || (fields[1] != "TCP4" && fields[1] != "TCP6") {
		return headerAddresses{}, false
	}
	src, e1 := netip.ParseAddr(fields[2])
	dst, e2 := netip.ParseAddr(fields[3])
	sport, ok1 := port(fields[4])
	dport, ok2 := port(fields[5])
	v4 := fields[1] == "TCP4"
	if e1 != nil || e2 != nil || !ok1 || !ok2 || src.Is4() != v4 || dst.Is4() != v4 || src.Zone() != "" || dst.Zone() != "" {
		return headerAddresses{}, false
	}
	return headerAddresses{netip.AddrPortFrom(src, sport), netip.AddrPortFrom(dst, dport)}, true
}

// An offset of zero requests more bytes, and a negative offset rejects the header.
func parseHeader(data []byte, transport byte) (headerAddresses, int) {
	if len(data) < 5 {
		return headerAddresses{}, 0
	}
	if bytes.HasPrefix(data, textSignature) {
		if transport != 1 {
			return headerAddresses{}, -1
		}
		line := data[:min(107, len(data))]
		end := bytes.IndexByte(line, '\n')
		if end < 0 {
			if len(data) >= 107 || bytes.IndexByte(line, 0) >= 0 {
				return headerAddresses{}, -1
			}
			return headerAddresses{}, 0
		}
		if end == 0 || line[end-1] != '\r' || bytes.IndexByte(line[:end], 0) >= 0 {
			return headerAddresses{}, -1
		}
		addr, ok := textAddresses(line[:end-1])
		if !ok {
			return headerAddresses{}, -1
		}
		return addr, end + 1
	}
	if len(data) < 16 {
		if !headerCandidate(data) {
			return headerAddresses{}, -1
		}
		return headerAddresses{}, 0
	}
	if !bytes.HasPrefix(data, signature) || data[12]>>4 != 2 {
		return headerAddresses{}, -1
	}
	body := int(binary.BigEndian.Uint16(data[14:]))
	end := 16 + body
	if len(data) < end {
		return headerAddresses{}, 0
	}
	switch data[12] & 15 {
	case 0:
		return headerAddresses{}, end
	case 1:
	default:
		return headerAddresses{}, -1
	}
	family := data[13]
	if family == 0 {
		return headerAddresses{}, end
	}
	if family&15 != transport {
		return headerAddresses{}, -1
	}
	switch {
	case family>>4 == 1 && body >= 12:
		return headerAddresses{
			netip.AddrPortFrom(netip.AddrFrom4([4]byte(data[16:20])), binary.BigEndian.Uint16(data[24:])),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte(data[20:24])), binary.BigEndian.Uint16(data[26:])),
		}, end
	case family>>4 == 2 && body >= 36:
		return headerAddresses{
			netip.AddrPortFrom(netip.AddrFrom16([16]byte(data[16:32])), binary.BigEndian.Uint16(data[48:])),
			netip.AddrPortFrom(netip.AddrFrom16([16]byte(data[32:48])), binary.BigEndian.Uint16(data[50:])),
		}, end
	default:
		return headerAddresses{}, -1
	}
}

func headerCandidate(data []byte) bool {
	for _, prefix := range [][]byte{textSignature, signature} {
		if bytes.Equal(data[:min(len(data), len(prefix))], prefix[:min(len(data), len(prefix))]) {
			return true
		}
	}
	return false
}
