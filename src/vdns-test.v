module main

import vdns


fn main() {
	resolver := '192.168.178.2:53'

	mut result := vdns.Response{}


	// Test A record
	print('Testing A record...')
	result = vdns.query(vdns.Query{ domain: 'fleximus.org', resolver: resolver }) !
	assert(result.answers[0].record == '95.216.116.79')
	println('OK!')

	// Test AAAA record
	print('Testing AAAA record...')
	result = vdns.query(vdns.Query{ domain: 'fleximus.org', @type: vdns.Type.aaaa, resolver: resolver }) !
	assert(result.answers[0].record == '2a01:04f9:002b:1a1c:5457:76dc:a4cf:0180')
	println('OK!')

	// Test CAA record
	print('Testing CAA record...')
	result = vdns.query(vdns.Query{ domain: 'fleximus.org', @type: vdns.Type.caa, resolver: resolver }) !
	assert(result.answers[0].record == '0 issue letsencrypt.org')
	println('OK!')

	// Test MX record
	print('Testing MX record...')
	result = vdns.query(vdns.Query{ domain: 'fleximus.org', @type: vdns.Type.mx, resolver: resolver }) !
	assert(result.answers[0].record == '10 bouncer.mxsystem.de')
	println('OK!')

	// Test TXT record
	print('Testing TXT record...')
	result = vdns.query(vdns.Query{ domain: 'fleximus.org', @type: vdns.Type.txt, resolver: resolver }) !
	assert(result.answers[0].record == 'v=spf1 mx -all')
	println('OK!')

	println("*** ALL TESTS PASSED ***")
}
