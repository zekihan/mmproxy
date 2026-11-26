//go:build linux

package main

import (
	"log/slog"
	"net/netip"
	"syscall"
	"time"
)

type flowKey struct {
	peer, source, destination netip.AddrPort
}

type udpFlow struct {
	key     flowKey
	fd      int
	peer    syscall.Sockaddr
	touched time.Time
}

type udpWorker struct {
	cfg    config
	limits *limits
	poll   *worker
	next   uint64
	ids    map[flowKey]uint64
	flows  map[uint64]*udpFlow
}

func (w *udpWorker) remove(id uint64) {
	if flow := w.flows[id]; flow != nil {
		delete(w.ids, flow.key)
		delete(w.flows, id)
		syscall.Close(flow.fd)
		w.limits.depart(1)
	}
}

func (w *udpWorker) getFlow(key flowKey, raw syscall.Sockaddr, now time.Time) (*udpFlow, error) {
	if id := w.ids[key]; id != 0 {
		return w.flows[id], nil
	}
	if !w.limits.admit(1) {
		return nil, syscall.EMFILE
	}
	success := false
	defer func() {
		if !success {
			w.limits.depart(1)
		}
	}()
	fd, target, err := dialSocket(w.cfg, key.peer, headerAddresses{key.source, key.destination}, syscall.SOCK_DGRAM)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !success {
			syscall.Close(fd)
		}
	}()
	if err := syscall.Connect(fd, target); err != nil {
		return nil, err
	}
	w.next++
	if err := w.poll.watch(syscall.EPOLL_CTL_ADD, fd, w.next, syscall.EPOLLIN); err != nil {
		return nil, err
	}
	flow := &udpFlow{key: key, fd: fd, peer: raw, touched: now}
	w.ids[key] = w.next
	w.flows[w.next] = flow
	success = true
	return flow, nil
}

func (w *udpWorker) receive(buffer []byte) {
	for range 64 {
		n, raw, err := syscall.Recvfrom(w.poll.listener, buffer, 0)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return
		}
		peer := peerAddress(raw)
		if !peer.IsValid() || !permitted(w.cfg.peers, peer.Addr().WithZone("")) {
			continue
		}
		addresses, offset := parseHeader(buffer[:n], 2)
		if offset <= 0 {
			continue
		}
		now := time.Now()
		destination := addresses.destination
		if !w.cfg.dynamic {
			destination = netip.AddrPort{}
		}
		flow, err := w.getFlow(flowKey{peer, addresses.source, destination}, raw, now)
		if err != nil {
			if w.cfg.verbose >= 1 {
				slog.Warn("UDP flow rejected", "peer", peer, "error", err)
			}
			continue
		}
		flow.touched = now
		if _, err = syscall.Write(flow.fd, buffer[offset:n]); err != nil && err != syscall.EAGAIN {
			w.remove(w.ids[flow.key])
		}
	}
}

func (w *udpWorker) reply(id uint64, buffer []byte) {
	flow := w.flows[id]
	if flow == nil {
		return
	}
	for range 64 {
		n, err := syscall.Read(flow.fd, buffer)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN {
			return
		}
		if err != nil {
			w.remove(id)
			return
		}
		flow.touched = time.Now()
		if err := syscall.Sendto(w.poll.listener, buffer[:n], 0, flow.peer); err != nil && err != syscall.EAGAIN {
			w.remove(id)
			return
		}
	}
}

func (w *udpWorker) run(done <-chan struct{}) error {
	defer func() {
		for id := range w.flows {
			w.remove(id)
		}
		syscall.Close(w.poll.listener)
		syscall.Close(w.poll.poller)
	}()
	events := make([]syscall.EpollEvent, 64)
	buffer := make([]byte, 65536)
	nextSweep := time.Now()
	wait := int(max(time.Millisecond, min(250*time.Millisecond, w.cfg.udpIdle)) / time.Millisecond)
	for {
		select {
		case <-done:
			return nil
		default:
		}
		if now := time.Now(); !now.Before(nextSweep) {
			for id, flow := range w.flows {
				if now.Sub(flow.touched) >= w.cfg.udpIdle {
					w.remove(id)
				}
			}
			nextSweep = now.Add(time.Duration(wait) * time.Millisecond)
		}
		n, err := syscall.EpollWait(w.poll.poller, events, wait)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		for _, e := range events[:n] {
			token := uint64(uint32(e.Fd)) | uint64(uint32(e.Pad))<<32
			if token == 0 {
				w.receive(buffer)
			} else if e.Events&syscall.EPOLLERR != 0 {
				w.remove(token)
			} else {
				w.reply(token, buffer)
			}
		}
	}
}

func runUDP(cfg config, limits *limits, done chan struct{}) error {
	workers := make([]*udpWorker, 0, cfg.workers)
	failed := func(err error) error {
		for _, w := range workers {
			syscall.Close(w.poll.poller)
			syscall.Close(w.poll.listener)
		}
		return err
	}
	for range cfg.workers {
		fd, err := listen(cfg, syscall.SOCK_DGRAM)
		if err != nil {
			return failed(err)
		}
		poller, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
		if err != nil {
			syscall.Close(fd)
			return failed(err)
		}
		poll := &worker{listener: fd, poller: poller}
		w := &udpWorker{cfg: cfg, limits: limits, poll: poll, ids: make(map[flowKey]uint64), flows: make(map[uint64]*udpFlow)}
		workers = append(workers, w)
		if err := poll.watch(syscall.EPOLL_CTL_ADD, fd, 0, syscall.EPOLLIN); err != nil {
			return failed(err)
		}
	}
	return serveWorkers(cfg, done, len(workers), func(i int) error { return workers[i].run(done) })
}
