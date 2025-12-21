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
	assert result.answers[0].record == '142.132.140.15'

	// Test A record (explicit)
	result = query(Query{ domain: 'fleximus.org', @type: .a, resolver: resolver }) !
	assert result.answers[0].record == '142.132.140.15'

	// Test AAAA record
	result = query(Query{ domain: 'fleximus.org', @type: .aaaa, resolver: resolver }) !
	assert result.answers[0].record == '2a01:4f8:261:1262:5457:76dc:a4cf:180'

	// Test CAA record
	result = query(Query{ domain: 'fleximus.org', @type: .caa, resolver: resolver }) !
	assert result.answers[0].record == '0 issue letsencrypt.org'

	// Test MX record
	result = query(Query{ domain: 'fleximus.org', @type: .mx, resolver: resolver }) !
	assert result.answers[0].record == '10 bouncer.mxsystem.de'

	// Test NULL-MX record
	result = query(Query{ domain: 'example.com', @type: .mx, resolver: resolver }) !
	assert result.answers[0].record == '0 .'

	// Test SRV record
	result = query(Query{ domain: '_imaps._tcp.gmail.com', @type: .srv, resolver: resolver }) !
	assert result.answers[0].record == '5 0 993 imap.gmail.com'

	// Test TLSA record
	result = query(Query{ domain: '_25._tcp.smtp.kernel-error.de', @type: .tlsa, resolver: resolver }) !
	mut answers := result.answers.clone()
	answers.sort(a.record < b.record)
	assert answers[0].record == '3 1 1 35CAFD57F224FEF9872C8201B070E4CAEC38E2DF5B981EFD70F6C9F7 C433B249'
	assert answers[1].record == '3 1 1 F39337ABC83C1E8F9FD374BF8BA80624D457F11C5367B65FCB0A2D73 1354BD9F'

	// Test TXT record
	result = query(Query{ domain: 'fleximus.org', @type: .txt, resolver: resolver }) !
	assert result.answers[0].record == 'v=spf1 mx -all'

	// Test TXT record (TCP fallback - google.com has many TXT records exceeding 512 bytes)
	result = query(Query{ domain: 'google.com', @type: .txt, resolver: resolver }) !
	assert result.answers.len > 10  // google.com has many TXT records

	// Test DNSKEY record
	result = query(Query{ domain: 'example.com', @type: .dnskey, resolver: resolver }) !
	dnskey_answers := result.answers.clone()
	answers.sort(a.record < b.record)
	assert dnskey_answers[0].record == '256 3 13 MjyZielP0GqniI1+j+wAG/3t0ImDDIlj1CxR0oobkZQHSKH2Fqx6tm2NcYu57POJ83SzCWLkqIjZHS1mh5wbaw=='
	assert dnskey_answers[1].record == '256 3 13 kxipjoIbNZDsWqEKaYaGq6fM/XThrRp1ue6AV9R/n3eWxpGCeCWJb47PEEEj/Q6VAYFW/7UFo5mXoZfxKYZa3A=='

	// Test URI record
	result = query(Query{ domain: '_https._tcp.fleximus.de', @type: .uri, resolver: resolver }) !
	assert result.answers[0].record == '10 1 https://fleximus.org'

	// Test AXFR (zone transfer) - zonetransfer.me allows public AXFR
	result = query(Query{ domain: 'zonetransfer.me', @type: .axfr, resolver: '81.4.108.41:53' }) !
	assert result.answers.len > 10  // Zone has many records
	// First and last records should be SOA
	assert result.answers[0].type == .soa
	assert result.answers[result.answers.len - 1].type == .soa
}

