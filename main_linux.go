//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	headerSize  = 8192
	budget      = 1024 * 1024
	pipeLimit   = 16
	edge        = 1 << 31
	reading     = syscall.EPOLLIN | syscall.EPOLLRDHUP | edge
	relaying    = reading | syscall.EPOLLOUT
	spliceFlags = 1 | 2 // SPLICE_F_MOVE | SPLICE_F_NONBLOCK
)

type state uint8

const (
	header state = iota
	connecting
	relay
)

type pipe [2]int
type direction struct {
	pipe    pipe
	pending int
	eof     bool
	buffer  []byte
	offset  int
}
type session struct {
	front, back      int
	peer             netip.AddrPort
	status           state
	queued           bool
	buffer           []byte
	used, consumed   int
	upload, download direction
}
type timer struct {
	id       uint64
	deadline time.Time
}
type queue[T any] struct {
	items []T
	head  int
}

func (q *queue[T]) empty() bool {
	return q.head == len(q.items)
}

func (q *queue[T]) push(item T) {
	q.items = append(q.items, item)
}

func (q *queue[T]) pop() T {
	item := q.items[q.head]
	q.head++
	if q.empty() {
		q.items = q.items[:0]
		q.head = 0
	} else if q.head >= 1024 && q.head >= len(q.items)/2 {
		q.items = q.items[:copy(q.items, q.items[q.head:])]
		q.head = 0
	}
	return item
}

type worker struct {
	poller, listener            int
	cfg                         config
	limits                      *limits
	next                        uint64
	sessions                    map[uint64]*session
	headers, dialing, detection queue[timer]
	ready                       queue[uint64]
	pipes                       []pipe
	acceptResume                time.Time
}

func (w *worker) watch(op, fd int, token uint64, events uint32) error {
	return syscall.EpollCtl(w.poller, op, fd, &syscall.EpollEvent{Events: events, Fd: int32(token), Pad: int32(token >> 32)})
}

func (w *worker) getPipe() (pipe, error) {
	if n := len(w.pipes); n > 0 {
		p := w.pipes[n-1]
		w.pipes = w.pipes[:n-1]
		return p, nil
	}
	if !reserve(&w.limits.fdUsed, 2, w.limits.fdMax) {
		return pipe{-1, -1}, syscall.EMFILE
	}
	var p pipe
	if err := syscall.Pipe2(p[:], syscall.O_NONBLOCK|syscall.O_CLOEXEC); err != nil {
		w.limits.fdUsed.Add(-2)
		return pipe{-1, -1}, err
	}
	_, _, _ = syscall.Syscall(syscall.SYS_FCNTL, uintptr(p[1]), syscall.F_SETPIPE_SZ, budget)
	return p, nil
}

func (w *worker) putPipe(flow *direction) {
	if flow.pipe[0] < 0 {
		return
	}
	if flow.pending == 0 && len(w.pipes) < pipeLimit {
		w.pipes = append(w.pipes, flow.pipe)
	} else {
		_ = syscall.Close(flow.pipe[0])
		_ = syscall.Close(flow.pipe[1])
		w.limits.fdUsed.Add(-2)
	}
	flow.pipe = pipe{-1, -1}
}

func (w *worker) destroy(id uint64, conn *session) {
	delete(w.sessions, id)
	w.limits.depart(2)
	_ = syscall.Close(conn.front)
	if conn.back >= 0 {
		_ = syscall.Close(conn.back)
	}
	w.putPipe(&conn.upload)
	w.putPipe(&conn.download)
}

func (w *worker) schedule(id uint64, conn *session) {
	if !conn.queued {
		conn.queued = true
		w.ready.push(id)
	}
}

func (w *worker) relayStart(id uint64, conn *session) error {
	conn.status = relay
	if err := w.watch(syscall.EPOLL_CTL_MOD, conn.front, id<<1, relaying); err != nil {
		return err
	}
	w.schedule(id, conn)
	return nil
}

func socketAddress(a netip.AddrPort) (syscall.Sockaddr, error) {
	ip := a.Addr().Unmap()
	if ip.Is4() {
		return &syscall.SockaddrInet4{Port: int(a.Port()), Addr: ip.As4()}, nil
	}
	sa := &syscall.SockaddrInet6{Port: int(a.Port()), Addr: ip.As16()}
	if ip.Zone() != "" {
		iface, err := net.InterfaceByName(ip.Zone())
		if err != nil {
			return nil, err
		}
		sa.ZoneId = uint32(iface.Index)
	}
	return sa, nil
}

func peerAddress(raw syscall.Sockaddr) netip.AddrPort {
	switch a := raw.(type) {
	case *syscall.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port))
	case *syscall.SockaddrInet6:
		ip := netip.AddrFrom16(a.Addr).Unmap()
		if a.ZoneId != 0 && ip.Is6() {
			if iface, err := net.InterfaceByIndex(int(a.ZoneId)); err == nil {
				ip = ip.WithZone(iface.Name)
			}
		}
		return netip.AddrPortFrom(ip, uint16(a.Port))
	default:
		return netip.AddrPort{}
	}
}

func setTransparent(fd int, ipv4 bool) error {
	if ipv4 {
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
	}
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, 75, 1)
}

func dialSocket(cfg config, peer netip.AddrPort, addresses headerAddresses, kind int) (int, syscall.Sockaddr, error) {
	targetAddr, err := cfg.target(peer, addresses.source, addresses.destination)
	if err != nil {
		return -1, nil, err
	}
	ipv4 := targetAddr.Addr().Unmap().Is4()
	family := syscall.AF_INET6
	if ipv4 {
		family = syscall.AF_INET
	}
	target, err := socketAddress(targetAddr)
	if err != nil {
		return -1, nil, err
	}
	fd, err := syscall.Socket(family, kind|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, nil, err
	}
	setup := func() error {
		if kind == syscall.SOCK_STREAM {
			if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err != nil {
				return err
			}
		}
		if !addresses.source.IsValid() {
			return nil
		}
		if addresses.source.Addr().Unmap().Is4() != ipv4 {
			return errors.New("source and destination families differ")
		}
		if err := setTransparent(fd, ipv4); err != nil {
			return err
		}
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			return err
		}
		if cfg.mark != 0 {
			if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, cfg.mark); err != nil {
				return err
			}
		}
		source, err := socketAddress(addresses.source)
		if err != nil {
			return err
		}
		return syscall.Bind(fd, source)
	}
	if err := setup(); err != nil {
		syscall.Close(fd)
		return -1, nil, err
	}
	return fd, target, nil
}

func (w *worker) dial(id uint64, conn *session, addresses headerAddresses) error {
	back, target, err := dialSocket(w.cfg, conn.peer, addresses, syscall.SOCK_STREAM)
	if err != nil {
		return err
	}
	conn.back = back
	if w.cfg.verbose >= 2 {
		slog.Info("backend dial", "peer", conn.peer, "source", addresses.source)
	}
	connect := syscall.Connect(back, target)
	if connect != nil && connect != syscall.EINPROGRESS {
		return connect
	}
	if err := w.watch(syscall.EPOLL_CTL_ADD, back, id<<1|1, relaying); err != nil {
		return err
	}
	if connect == nil {
		return w.relayStart(id, conn)
	}
	conn.status = connecting
	w.dialing.push(timer{id, time.Now().Add(2 * time.Second)})
	return nil
}

func (w *worker) readHeader(id uint64, conn *session) bool {
	for {
		n, err := syscall.Read(conn.front, conn.buffer[conn.used:])
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN {
			return true
		}
		if err != nil || n == 0 {
			return false
		}
		conn.used += n
		data := conn.buffer[:conn.used]
		if w.cfg.mixed && !headerCandidate(data) {
			return w.dialHeader(id, conn, headerAddresses{source: conn.peer})
		}
		address, offset := parseHeader(data, 1)
		if offset < 0 {
			return false
		}
		if offset > 0 {
			conn.consumed = offset
			return w.dialHeader(id, conn, address)
		}
		if conn.used == len(conn.buffer) {
			if conn.used == maxHeader {
				return false
			}
			conn.buffer = append(conn.buffer, make([]byte, min(conn.used, maxHeader-conn.used))...)
		}
	}
}

func (w *worker) dialHeader(id uint64, conn *session, addresses headerAddresses) bool {
	if err := w.dial(id, conn, addresses); err != nil {
		if w.cfg.verbose >= 1 {
			slog.Warn("backend dial failed", "peer", conn.peer, "error", err)
		}
		return false
	}
	return true
}

func pumpBuffered(flow *direction, src, dst int) (bool, error) {
	for copied := 0; copied < budget; {
		if flow.pending > 0 {
			n, err := syscall.Write(dst, flow.buffer[flow.offset:flow.offset+flow.pending])
			if err == syscall.EINTR {
				continue
			}
			if err == syscall.EAGAIN {
				return false, nil
			}
			if err != nil || n <= 0 {
				return false, syscall.EIO
			}
			flow.offset += n
			flow.pending -= n
			copied += n
			continue
		}
		n, err := syscall.Read(src, flow.buffer)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN {
			flow.buffer = nil
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if n == 0 {
			flow.buffer = nil
			flow.eof = true
			return false, halfClose(dst)
		}
		flow.offset, flow.pending = 0, n
	}
	return true, nil
}

func halfClose(fd int) error {
	if err := syscall.Shutdown(fd, syscall.SHUT_WR); err != syscall.ENOTCONN {
		return err
	}
	return nil
}

func splice(src, dst, count int) (int, error) {
	// All relay sockets and pipes are nonblocking. The epoll wait yields to the scheduler.
	n, _, errno := syscall.RawSyscall6(syscall.SYS_SPLICE, uintptr(src), 0, uintptr(dst), 0,
		uintptr(count), spliceFlags)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

func (w *worker) pump(flow *direction, src, dst int) (bool, error) {
	if flow.eof {
		return false, nil
	}
	if flow.buffer != nil {
		return pumpBuffered(flow, src, dst)
	}
	for copied := 0; copied < budget; {
		if flow.pending != 0 {
			n, err := splice(flow.pipe[0], dst, flow.pending)
			if err == syscall.EINTR {
				continue
			}
			if err == syscall.EAGAIN {
				return false, nil
			}
			if err != nil || n <= 0 {
				return false, syscall.EIO
			}
			flow.pending -= int(n)
			copied += int(n)
			continue
		}
		if flow.pipe[0] < 0 {
			p, err := w.getPipe()
			if err != nil {
				if err != syscall.EMFILE && err != syscall.ENFILE {
					return false, err
				}
				flow.buffer = make([]byte, 16*1024)
				return pumpBuffered(flow, src, dst)
			}
			flow.pipe = p
		}
		n, err := splice(src, flow.pipe[1], budget)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN {
			w.putPipe(flow)
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if n == 0 {
			w.putPipe(flow)
			flow.eof = true
			err := syscall.Shutdown(dst, syscall.SHUT_WR)
			if err == syscall.ENOTCONN {
				err = nil
			}
			return false, err
		}
		flow.pending = int(n)
	}
	if flow.pending == 0 {
		w.putPipe(flow)
	}
	return true, nil
}

func (w *worker) service(id uint64, conn *session) {
	for conn.consumed < conn.used {
		n, err := syscall.Write(conn.back, conn.buffer[conn.consumed:conn.used])
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN {
			break
		}
		if err != nil || n == 0 {
			w.destroy(id, conn)
			return
		}
		conn.consumed += n
	}
	var upload bool
	if conn.consumed == conn.used {
		conn.buffer = nil
		var err error
		upload, err = w.pump(&conn.upload, conn.front, conn.back)
		if err != nil {
			w.destroy(id, conn)
			return
		}
	}
	download, err := w.pump(&conn.download, conn.back, conn.front)
	if err != nil || (conn.upload.eof && conn.download.eof) {
		w.destroy(id, conn)
	} else if upload || download {
		w.schedule(id, conn)
	}
}

func (w *worker) event(token uint64, event uint32) {
	id := token >> 1
	conn := w.sessions[id]
	if conn == nil {
		return
	}
	if event&syscall.EPOLLERR != 0 {
		w.destroy(id, conn)
		return
	}
	switch conn.status {
	case header:
		if !w.readHeader(id, conn) {
			w.destroy(id, conn)
		}
	case connecting:
		if token&1 != 0 {
			code, err := syscall.GetsockoptInt(conn.back, syscall.SOL_SOCKET, syscall.SO_ERROR)
			if err != nil || code != 0 || w.relayStart(id, conn) != nil {
				w.destroy(id, conn)
			}
		}
	case relay:
		w.schedule(id, conn)
	}
}

func (w *worker) accept() {
	for i := 0; i < 64; i++ {
		fd, remote, err := syscall.Accept4(w.listener, syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			if (err == syscall.EMFILE || err == syscall.ENFILE) &&
				syscall.EpollCtl(w.poller, syscall.EPOLL_CTL_DEL, w.listener, nil) == nil {
				w.acceptResume = time.Now().Add(50 * time.Millisecond)
			}
			return
		}
		peer := peerAddress(remote)
		if !peer.IsValid() || !permitted(w.cfg.peers, peer.Addr().WithZone("")) ||
			syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1) != nil || !w.limits.admit(2) {
			_ = syscall.Close(fd)
			continue
		}
		w.next++
		id := w.next
		conn := &session{front: fd, peer: peer, back: -1, buffer: make([]byte, headerSize), upload: direction{pipe: pipe{-1, -1}}, download: direction{pipe: pipe{-1, -1}}}
		if w.watch(syscall.EPOLL_CTL_ADD, fd, id<<1, reading) != nil {
			_ = syscall.Close(fd)
			w.limits.depart(2)
			continue
		}
		w.sessions[id] = conn
		now := time.Now()
		w.headers.push(timer{id, now.Add(w.cfg.headerTimeout)})
		if w.cfg.mixed {
			w.detection.push(timer{id, now.Add(w.cfg.detectTimeout)})
		}
	}
}

func (w *worker) expire(timers *queue[timer], expected state, now time.Time) int {
	for !timers.empty() {
		item := timers.items[timers.head]
		conn := w.sessions[item.id]
		if conn != nil && conn.status == expected {
			if remaining := item.deadline.Sub(now); remaining > 0 {
				return int((remaining + time.Millisecond - 1) / time.Millisecond)
			}
			w.destroy(item.id, conn)
		}
		timers.pop()
	}
	return -1
}

func (w *worker) detectRaw(now time.Time) int {
	for !w.detection.empty() {
		item := w.detection.items[w.detection.head]
		conn := w.sessions[item.id]
		if conn != nil && conn.status == header && conn.used == 0 {
			if remaining := item.deadline.Sub(now); remaining > 0 {
				return int((remaining + time.Millisecond - 1) / time.Millisecond)
			}
			if !w.readHeader(item.id, conn) ||
				(conn.status == header && conn.used == 0 && !w.dialHeader(item.id, conn, headerAddresses{source: conn.peer})) {
				w.destroy(item.id, conn)
			}
		}
		w.detection.pop()
	}
	return -1
}

func (w *worker) run(done <-chan struct{}) error {
	events := make([]syscall.EpollEvent, 64)
	var drainUntil time.Time
	for {
		select {
		case <-done:
			if drainUntil.IsZero() {
				_ = syscall.EpollCtl(w.poller, syscall.EPOLL_CTL_DEL, w.listener, nil)
				_ = syscall.Close(w.listener)
				w.listener = -1
				w.acceptResume = time.Time{}
				drainUntil = time.Now().Add(5 * time.Second)
			}
			if len(w.sessions) == 0 || !time.Now().Before(drainUntil) {
				return nil
			}
		default:
		}
		now := time.Now()
		timeout := w.expire(&w.headers, header, now)
		if next := w.expire(&w.dialing, connecting, now); next >= 0 && (timeout < 0 || next < timeout) {
			timeout = next
		}
		if next := w.detectRaw(now); next >= 0 && (timeout < 0 || next < timeout) {
			timeout = next
		}
		if !w.acceptResume.IsZero() {
			if next := w.acceptResume.Sub(now); next > 0 {
				rounded := int((next + time.Millisecond - 1) / time.Millisecond)
				if timeout < 0 || rounded < timeout {
					timeout = rounded
				}
			} else {
				if err := w.watch(syscall.EPOLL_CTL_ADD, w.listener, 0, syscall.EPOLLIN); err != nil {
					return err
				}
				w.acceptResume = time.Time{}
			}
		}
		if !w.ready.empty() {
			timeout = 0
		}
		if timeout < 0 || timeout > 250 {
			timeout = 250
		}
		n, err := syscall.EpollWait(w.poller, events, timeout)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		for _, e := range events[:n] {
			token := uint64(uint32(e.Fd)) | uint64(uint32(e.Pad))<<32
			if token == 0 {
				if w.listener >= 0 {
					w.accept()
				}
			} else {
				w.event(token, e.Events)
			}
		}
		for i := 0; i < 64 && !w.ready.empty(); i++ {
			id := w.ready.pop()
			if conn := w.sessions[id]; conn != nil {
				conn.queued = false
				w.service(id, conn)
			}
		}
	}
}

func listen(cfg config, kind int) (int, error) {
	family := syscall.AF_INET
	if !cfg.front.Addr().Unmap().Is4() {
		family = syscall.AF_INET6
	}
	address, err := socketAddress(cfg.front)
	if err != nil {
		return -1, err
	}
	fd, err := syscall.Socket(family, kind|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	setup := func() error {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			return err
		}
		if cfg.workers > 1 {
			if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, 15, 1); err != nil {
				return err
			}
		}
		if cfg.transparent {
			if err := setTransparent(fd, family == syscall.AF_INET); err != nil {
				return err
			}
		}
		if err := syscall.Bind(fd, address); err != nil {
			return err
		}
		if kind == syscall.SOCK_STREAM {
			return syscall.Listen(fd, 4096)
		}
		return nil
	}
	if err := setup(); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func newWorker(cfg config, limits *limits) (*worker, error) {
	poller, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}
	listener, err := listen(cfg, syscall.SOCK_STREAM)
	if err != nil {
		syscall.Close(poller)
		return nil, err
	}
	w := &worker{poller: poller, listener: listener, sessions: make(map[uint64]*session), cfg: cfg, limits: limits}
	return w, w.watch(syscall.EPOLL_CTL_ADD, listener, 0, syscall.EPOLLIN)
}

func (w *worker) close() {
	for id, conn := range w.sessions {
		w.destroy(id, conn)
	}
	for _, p := range w.pipes {
		syscall.Close(p[0])
		syscall.Close(p[1])
		w.limits.fdUsed.Add(-2)
	}
	if w.listener >= 0 {
		syscall.Close(w.listener)
	}
	syscall.Close(w.poller)
}

func run(cfg config, limits *limits, done chan struct{}) error {
	if cfg.protocol == "udp" {
		return runUDP(cfg, limits, done)
	}
	workers := make([]*worker, 0, cfg.workers)
	for range cfg.workers {
		w, err := newWorker(cfg, limits)
		if w != nil {
			workers = append(workers, w)
		}
		if err != nil {
			for _, worker := range workers {
				worker.close()
			}
			return err
		}
	}
	return serveWorkers(cfg, done, len(workers), func(i int) error {
		defer workers[i].close()
		return workers[i].run(done)
	})
}

func serveWorkers(cfg config, done chan struct{}, count int, work func(int) error) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	var group sync.WaitGroup
	failed := make(chan error, count)
	for i := range count {
		group.Go(func() {
			if err := work(i); err != nil {
				failed <- err
			}
		})
	}
	slog.Info("listening", "protocol", cfg.protocol, "address", cfg.front, "listeners", count)
	var err error
	select {
	case err = <-failed:
	case <-signals:
	}
	close(done)
	group.Wait()
	return err
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	cfg, err := readConfig(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if cfg.version {
		fmt.Println("mmproxy", version)
		return
	}
	if err = configureRouting(os.Getenv); err != nil {
		slog.Error("configure routing", "error", err)
		os.Exit(1)
	}
	limits, err := newLimits(cfg)
	if err == nil {
		err = run(cfg, limits, make(chan struct{}))
	}
	if err != nil {
		slog.Error("serve", "error", err)
		os.Exit(1)
	}
}
