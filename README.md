# mmproxy

A Linux PROXY protocol relay that forwards TCP streams and UDP datagrams to fixed or explicitly enabled dynamic destinations. The TCP frontend uses epoll and borrows splice pipes only while a direction has work. UDP flows and TCP sessions use the same admission and descriptor budget.

```sh
mmproxy -p tcp -l 127.0.0.1:2222 -4 127.0.0.1:2223 -6 '[::1]:2223' \
  -allowed-subnets /etc/go-mmproxy/allowed-subnets.txt -v 1
```

Use a peer allowlist on every production listener. PROXY headers are required by default. For TCP, `-allow-raw-tcp` requires a nonempty peer allowlist and enables transparent forwarding of raw peer addresses. `-raw-detection-timeout` defaults to 200 ms, and incomplete PROXY prefixes use the regular header deadline.

`-dynamic-destination` allows trusted peers to supply a destination. Use `-allowed-destinations` to restrict dynamic destination CIDRs. Valid addressless headers select the fixed backend by frontend family and use an ordinary backend connection. UDP accepts PROXY v2 datagrams and `-close-after` configures flow idle expiry.

Run with `CAP_NET_ADMIN` for transparent forwarding and built-in routing. Set `MMPROXY_SETUP_ROUTING=true` to install loopback routes and rules in the process network namespace. The default table is 123 and default rule priority is 32765. Override them with `MMPROXY_ROUTING_TABLE` and `MMPROXY_ROUTING_PRIORITY`. Existing matching entries stay in place. Conflicting entries stop startup. The process leaves policy routing installed on exit.

The relay and parser are first-party. The policy routing encoder and environment contract derive from the first-party dockerfiles mmproxy entrypoint. The upstream v2.3.1 binary is only built inside compatibility tests.

Run `go test -race ./...` and `go vet ./...` locally. The CI namespace test installs routing in an isolated network namespace and compares TCP and UDP forwarding against v2.3.1. Release binaries target Linux amd64 and arm64.
