# DNS

This is a DNS library written in V.


## Features

Supported query types:
- [x] A
- [x] AAAA
- [ ] AXFR
- [x] CAA
- [x] CNAME
- [x] PTR
- [x] MX
- [x] NS
- [x] SOA
- [x] TXT

## Installation

You can install this package either from [VPM] or from GitHub:

```txt
v install fleximus.vdns
v install --git https://github.com/fleximus/vdns
```

## Usage

To use `vdns` to run queries, you need to know and use the resolver's IP address, here in our example we make use of `192.168.0.1:53` that also includes the port `udp/53`.

```v
import fleximus.vdns

fn main() {
	resolver := '192.168.0.1:53'

	result = vdns.query(vdns.Query{ domain: 'gmail.com', @type: vdns.Type.mx, resolver: resolver }) or { panic('Failed query') }
	for answer in result.answers {
		println("${answer.name} ${answer.class} ${answer.ttl} ${answer.@type} ${answer.record}")
	}}
```

Please do NOT use in production.

## License

MIT