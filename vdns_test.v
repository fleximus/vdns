module vdns

fn test_str_to_type() {
	assert str_to_type('a') == Type.a
	assert str_to_type('aaaa') == Type.aaaa
	assert str_to_type('axfr') == Type.axfr
	assert str_to_type('caa') == Type.caa
	assert str_to_type('cname') == Type.cname
	assert str_to_type('ixfr') == Type.ixfr
	assert str_to_type('mx') == Type.mx
	assert str_to_type('ns') == Type.ns
	assert str_to_type('ptr') == Type.ptr
	assert str_to_type('soa') == Type.soa
	assert str_to_type('spf') == Type.spf
	assert str_to_type('txt') == Type.txt
}
/*
fn test_type_to_str() {
	assert vdns.type_to_str(vdns.Type.a) == 'a'
	assert vdns.type_to_str(vdns.Type.aaaa) == 'aaaa'
	assert vdns.type_to_str(vdns.Type.axfr) == 'axfr'
	assert vdns.type_to_str(vdns.Type.caa) == 'caa'
	assert vdns.type_to_str(vdns.Type.cname) == 'cname'
	assert vdns.type_to_str(vdns.Type.ixfr) == 'ixfr'
	assert vdns.type_to_str(vdns.Type.mx) == 'mx'
	assert vdns.type_to_str(vdns.Type.ns) == 'ns'
	assert vdns.type_to_str(vdns.Type.ptr) == 'ptr'
	assert vdns.type_to_str(vdns.Type.soa) == 'soa'
	assert vdns.type_to_str(vdns.Type.spf) == 'spf'
	assert vdns.type_to_str(vdns.Type.txt) == 'txt'
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

	// Test TXT record
	result = vdns.query(vdns.Query{ domain: 'fleximus.org', @type: vdns.Type.txt, resolver: resolver }) !
	assert result.answers[0].record == 'v=spf1 mx -all'
}
*/