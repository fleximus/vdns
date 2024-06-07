module vdns

fn test_str_to_type() {
	assert str_to_type('a') == Type.a
	assert str_to_type('aaaa') == Type.aaaa
	assert str_to_type('axfr') == Type.axfr
	assert str_to_type('caa') == Type.caa
	assert str_to_type('cname') == Type.cname
	assert str_to_type('dnskey') == Type.dnskey
	assert str_to_type('ixfr') == Type.ixfr
	assert str_to_type('mx') == Type.mx
	assert str_to_type('ns') == Type.ns
	assert str_to_type('ptr') == Type.ptr
	assert str_to_type('soa') == Type.soa
	assert str_to_type('spf') == Type.spf
	assert str_to_type('tlsa') == Type.tlsa
	assert str_to_type('txt') == Type.txt
	assert str_to_type('uri') == Type.uri
}

fn test_type_to_str() {
	assert vdns.type_to_str(vdns.Type.a) == 'a'
	assert vdns.type_to_str(vdns.Type.aaaa) == 'aaaa'
	assert vdns.type_to_str(vdns.Type.axfr) == 'axfr'
	assert vdns.type_to_str(vdns.Type.caa) == 'caa'
	assert vdns.type_to_str(vdns.Type.cname) == 'cname'
	assert vdns.type_to_str(vdns.Type.dnskey) == 'dnskey'
	assert vdns.type_to_str(vdns.Type.ixfr) == 'ixfr'
	assert vdns.type_to_str(vdns.Type.mx) == 'mx'
	assert vdns.type_to_str(vdns.Type.ns) == 'ns'
	assert vdns.type_to_str(vdns.Type.ptr) == 'ptr'
	assert vdns.type_to_str(vdns.Type.soa) == 'soa'
	assert vdns.type_to_str(vdns.Type.spf) == 'spf'
	assert vdns.type_to_str(vdns.Type.tlsa) == 'tlsa'
	assert vdns.type_to_str(vdns.Type.txt) == 'txt'
	assert vdns.type_to_str(vdns.Type.uri) == 'uri'
}

fn test_shorten_ipv6() {
	assert vdns.shorten_ipv6('2a01:04f9:002b:1a1c:5457:76dc:a4cf:0180') == '2a01:4f9:2b:1a1c:5457:76dc:a4cf:180'
	assert vdns.shorten_ipv6('2041:0000:140f:0000:0000:0000:875b:131b') == '2041:0:140f::875b:131b'	
}

fn test_vdns() {
	resolver := '1.1.1.1:53'
	mut result := vdns.Response{}

	// Test A record
	result = vdns.query(vdns.Query{ domain: 'fleximus.org', resolver: resolver }) !
	assert result.answers[0].record == '95.216.116.79'

	// Test AAAA record
	result = vdns.query(vdns.Query{ domain: 'fleximus.org', @type: vdns.Type.aaaa, resolver: resolver }) !
	assert result.answers[0].record == '2a01:4f9:2b:1a1c:5457:76dc:a4cf:180'

	// Test CAA record
	result = vdns.query(vdns.Query{ domain: 'fleximus.org', @type: vdns.Type.caa, resolver: resolver }) !
	assert result.answers[0].record == '0 issue letsencrypt.org'

	// Test MX record
	result = vdns.query(vdns.Query{ domain: 'fleximus.org', @type: vdns.Type.mx, resolver: resolver }) !
	assert result.answers[0].record == '10 bouncer.mxsystem.de'

	// Test TLSA record
	result = vdns.query(vdns.Query{ domain: '_25._tcp.smtp.kernel-error.de', @type: vdns.Type.tlsa, resolver: resolver }) !
	mut answers := result.answers.clone()
	answers.sort(a.record < b.record)
	assert answers[0].record == '3 1 1 16F49623BB0E75FAE4CD1C562BF20AE5DB8303AF7101856ED262E257 9CE03BCB'
	assert answers[1].record == '3 1 1 1771FB07FD574EE9D9F571AB2985CC8F20F309B6BB642742482AAB7F 3D466D9D'

	// Test TXT record
	result = vdns.query(vdns.Query{ domain: 'fleximus.org', @type: vdns.Type.txt, resolver: resolver }) !
	assert result.answers[0].record == 'v=spf1 mx -all'

	// Test DNSKEY record
	result = vdns.query(vdns.Query{ domain: 'example.com', @type: vdns.Type.dnskey, resolver: resolver }) !
	dnskey_answers := result.answers.clone()
	answers.sort(a.record < b.record)
	assert dnskey_answers[0].record == '256 3 13 nGzka+/3LSNN+P6JHx7Co8pdJ8Vjr2muj9neZK31FqTTEQkB/kQauyjLBxFwLgZcotUBgEu2+K/SWG4jAsW5+Q=='
	assert dnskey_answers[1].record == '257 3 13 kXKkvWU3vGYfTJGl3qBd4qhiWp5aRs7YtkCJxD2d+t7KXqwahww5IgJtxJT2yFItlggazyfXqJEVOmMJ3qT0tQ=='

	// Test URI record
	result = vdns.query(vdns.Query{ domain: '_https._tcp.fleximus.de', @type: vdns.Type.uri, resolver: resolver }) !
	assert result.answers[0].record == '10 1 https://fleximus.org'
}

