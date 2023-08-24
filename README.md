# VDNS

This is a DNS library written in V.

## Features

Supported query types:
- [x] A
- [x] AAAA
- [ ] AXFR
- [x] CAA
- [x] CNAME
- [x] DNSKEY
- [x] PTR
- [x] MX
- [x] NS
- [x] SOA
- [x] TLSA
- [x] TXT
- [x] URI

## Installation

You can install this package either from [VPM] or from GitHub:

```txt
v install fleximus.vdns
v install --git https://github.com/fleximus/vdns
```

## Usage

To use `vdns` in order to run queries, you need to specify the resolver's IP address, here in our example we make use of Cloudflares public 1.1.1.1 resolver.

```v
import fleximus.vdns

fn main() {
	resolver := '1.1.1.1:53'

	result := vdns.query(vdns.Query{ domain: 'gmail.com', @type: vdns.Type.mx, resolver: resolver }) or { panic('Failed query') }
	for answer in result.answers {
		println("${answer.name} ${answer.class} ${answer.ttl} ${answer.@type} ${answer.record}")
	}
}
```

This library is under development: **Do NOT use in production!**

## License

MIT
