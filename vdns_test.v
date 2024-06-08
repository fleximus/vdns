module vdns

fn test_str_to_type() {
	assert str_to_type('a')      == .a
	assert str_to_type('aaaa')   == .aaaa
	assert str_to_type('axfr')   == .axfr
	assert str_to_type('caa')    == .caa
	assert str_to_type('cname')  == .cname
	assert str_to_type('dnskey') == .dnskey
	assert str_to_type('ixfr')   == .ixfr
	assert str_to_type('mx')     == .mx
	assert str_to_type('ns')     == .ns
	assert str_to_type('ptr')    == .ptr
	assert str_to_type('soa')    == .soa
	assert str_to_type('spf')    == .spf
	assert str_to_type('tlsa')   == .tlsa
	assert str_to_type('txt')    == .txt
	assert str_to_type('uri')    == .uri
}

fn test_type_to_str() {
	assert type_to_str(.a)      == 'a'
	assert type_to_str(.aaaa)   == 'aaaa'
	assert type_to_str(.axfr)   == 'axfr'
	assert type_to_str(.caa)    == 'caa'
	assert type_to_str(.cname)  == 'cname'
	assert type_to_str(.dnskey) == 'dnskey'
	assert type_to_str(.ixfr)   == 'ixfr'
	assert type_to_str(.mx)     == 'mx'
	assert type_to_str(.ns)     == 'ns'
	assert type_to_str(.ptr)    == 'ptr'
	assert type_to_str(.soa)    == 'soa'
	assert type_to_str(.spf)    == 'spf'
	assert type_to_str(.tlsa)   == 'tlsa'
	assert type_to_str(.txt)    == 'txt'
	assert type_to_str(.uri)    == 'uri'
}

fn test_shorten_ipv6() {
	assert shorten_ipv6('2a01:04f9:002b:1a1c:5457:76dc:a4cf:0180') == '2a01:4f9:2b:1a1c:5457:76dc:a4cf:180'
	assert shorten_ipv6('2041:0000:140f:0000:0000:0000:875b:131b') == '2041:0:140f::875b:131b'	
}

fn test_vdns() {
	mut resolver := '1.1.1.1:53'
	mut result := vdns.Response{}

	// Test A record (implicit)
	result = query(Query{ domain: 'fleximus.org', resolver: resolver }) !
	assert result.answers[0].record == '95.216.116.79'

	// Test A record (explicit)
	result = query(Query{ domain: 'fleximus.org', @type: .a, resolver: resolver }) !
	assert result.answers[0].record == '95.216.116.79'

	// Test AAAA record
	result = query(Query{ domain: 'fleximus.org', @type: .aaaa, resolver: resolver }) !
	assert result.answers[0].record == '2a01:4f9:2b:1a1c:5457:76dc:a4cf:180'

	// Test CAA record
	result = query(Query{ domain: 'fleximus.org', @type: .caa, resolver: resolver }) !
	assert result.answers[0].record == '0 issue letsencrypt.org'

	// Test MX record
	result = query(Query{ domain: 'fleximus.org', @type: .mx, resolver: resolver }) !
	assert result.answers[0].record == '10 bouncer.mxsystem.de'

	// Test TLSA record
	result = query(Query{ domain: '_25._tcp.smtp.kernel-error.de', @type: .tlsa, resolver: resolver }) !
	mut answers := result.answers.clone()
	answers.sort(a.record < b.record)
	assert answers[0].record == '3 1 1 16F49623BB0E75FAE4CD1C562BF20AE5DB8303AF7101856ED262E257 9CE03BCB'
	assert answers[1].record == '3 1 1 1771FB07FD574EE9D9F571AB2985CC8F20F309B6BB642742482AAB7F 3D466D9D'

	// Test TXT record
	result = query(Query{ domain: 'fleximus.org', @type: .txt, resolver: resolver }) !
	assert result.answers[0].record == 'v=spf1 mx -all'

	// Test DNSKEY record
	result = query(Query{ domain: 'example.com', @type: .dnskey, resolver: resolver }) !
	dnskey_answers := result.answers.clone()
	answers.sort(a.record < b.record)
	assert dnskey_answers[0].record == '256 3 13 nGzka+/3LSNN+P6JHx7Co8pdJ8Vjr2muj9neZK31FqTTEQkB/kQauyjLBxFwLgZcotUBgEu2+K/SWG4jAsW5+Q=='
	assert dnskey_answers[1].record == '257 3 13 kXKkvWU3vGYfTJGl3qBd4qhiWp5aRs7YtkCJxD2d+t7KXqwahww5IgJtxJT2yFItlggazyfXqJEVOmMJ3qT0tQ=='

	// Test URI record
	result = query(Query{ domain: '_https._tcp.fleximus.de', @type: .uri, resolver: resolver }) !
	assert result.answers[0].record == '10 1 https://fleximus.org'
}

