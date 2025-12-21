module vdns

import net
import encoding.binary
import encoding.base64
import rand

pub enum Type as u16 {
	a      =   1  // RFC1035: a host address
	ns     =   2  // RFC1035: an authorative name server
	cname  =   5  // RFC1035: the cononical name for an alias
	soa    =   6  // RFC1035: marks the start of a zone of authority
	ptr    =  12  // RFC1035: domain name pointer
	mx     =  15  // RFC1035: mail exchange
	txt    =  16  // RFC1035: text strings
	aaaa   =  28  // RFC3596: IPv6 host address
	srv    =  33  // RFC2782: Service record
	cert   =  37  // RFC4398: Certificate record
	dnskey =  48  // RFC4034: Resource Records for the DNS Security Extensions
	tlsa   =  52  // RFC6698: The DNS-Based Authentication of Named Entities (DANE)
	              //          Transport Layer Security (TLS) Protocol: TLSA
	spf    =  99  // RFC7208: Sender Policy Framework (SPF)
	tsig   = 250  // RFC2845: Transaction Signature
	ixfr   = 251  // RFC5936: incremental zone transfer
	axfr   = 252  // RFC5936: zone transfer
	any    = 255  // RFC1035: any record
	uri    = 256  // RFC7553: The Uniform Resource Identifier (URI) DNS Resource Record
	caa    = 257  // RFC6844: certificate authority authorization 
}

enum Class as u16 {
	in   =   1  // RFC1035: the Internet
	cs   =   2  // RFC1035: the CHAOS class
	ch   =   3  // RFC1035: the CHAOS class
	hs   =   4
	none = 254  // RFC2136
	any  = 255  // RFC1035: ANY
}

fn int_to_class(i int) Class {
	return match i {
		int(Class.in) { Class.in }
		int(Class.cs) { Class.cs }
		int(Class.ch) { Class.ch }
		int(Class.hs) { Class.hs }
		int(Class.none) { Class.none }
		int(Class.any) { Class.any }
		else {
			eprintln('unsupported class ${i}')
			return Class.in  // Default to IN class
		}
	}
}

@[flag]
enum Flags as u16 {
	response             //  0
	b2                   //  1
	b3                   //  2
	b4                   //  3
	b5                   //  4
	b6                   //  5
	authorative_answer   //  6
	truncated_response   //  7
	recursion_desired    //  8
	recursion_available  //  9
	reserved            // 10
	authentic_data      // 11
	checking_disabled   // 12
	b13                 // 13
	b14                 // 14
	b15                 // 15
}

pub struct Query {
	transaction_id u16 = u16(rand.i16())
	flags Flags = Flags.recursion_desired
	questions u16 = 1
	answer_rrs u16
	auth_rrs u16
	additional_rrs u16
	// ------------------
pub:
	domain string
	type Type  = Type.a
	class Class = Class.in
	resolver string
	tcp bool    // Force TCP transport
	serial u32  // Current SOA serial for IXFR queries
}

pub struct Answer {
pub:
	name string
	type Type
	class Class
	ttl u32
	record string
}

pub struct Response {
pub:
	answers []Answer
}

fn query_to_buf(q Query) []u8 {
	mut buf := []u8{len: 12 }

	binary.big_endian_put_u16_at(mut buf, q.transaction_id, 0)
	binary.big_endian_put_u16_at(mut buf, u16(q.flags), 2)
	binary.big_endian_put_u16_at(mut buf, q.questions, 4)
	binary.big_endian_put_u16_at(mut buf, q.answer_rrs, 6)
	binary.big_endian_put_u16_at(mut buf, q.auth_rrs, 8)
	binary.big_endian_put_u16_at(mut buf, q.additional_rrs, 10)
	buf << str2dns(q.domain)
	buf << [u8(0), 0, 0, 0]  // array expansion for type and class
	binary.big_endian_put_u16_at(mut buf, u16(q.type), 14 + q.domain.len)
	binary.big_endian_put_u16_at(mut buf, u16(q.class), 16 + q.domain.len)

	return buf
}

fn query_to_buf_tcp(q Query) []u8 {
	dns_msg := query_to_buf(q)
	mut buf := []u8{len: 2}
	binary.big_endian_put_u16_at(mut buf, u16(dns_msg.len), 0)
	buf << dns_msg
	return buf
}

fn is_truncated(buf []u8) bool {
	flags := binary.big_endian_u16_at(buf, 2)
	return (flags & 0x0200) != 0  // TC flag is bit 9
}

fn query_to_buf_ixfr(q Query) []u8 {
	mut buf := []u8{len: 12}

	// Header
	binary.big_endian_put_u16_at(mut buf, q.transaction_id, 0)
	binary.big_endian_put_u16_at(mut buf, u16(q.flags), 2)
	binary.big_endian_put_u16_at(mut buf, 1, 4)   // questions = 1
	binary.big_endian_put_u16_at(mut buf, 0, 6)   // answers = 0
	binary.big_endian_put_u16_at(mut buf, 1, 8)   // auth_rrs = 1 (SOA)
	binary.big_endian_put_u16_at(mut buf, 0, 10)  // additional = 0

	// Question section
	domain_encoded := str2dns(q.domain)
	buf << domain_encoded
	buf << [u8(0), 0, 0, 0]  // placeholder for type and class
	question_end := 12 + domain_encoded.len
	binary.big_endian_put_u16_at(mut buf, u16(Type.ixfr), question_end)
	binary.big_endian_put_u16_at(mut buf, u16(q.class), question_end + 2)

	// Authority section - SOA record
	// Name (compressed pointer to question domain at offset 12)
	buf << [u8(0xc0), 0x0c]
	// Type = SOA (6)
	buf << [u8(0), 6]
	// Class = IN (1)
	buf << [u8(0), 1]
	// TTL = 0
	buf << [u8(0), 0, 0, 0]

	// RDATA for minimal SOA (server only needs serial)
	mut rdata := []u8{}
	rdata << 0  // MNAME = "." (root)
	rdata << 0  // RNAME = "." (root)
	// Serial (4 bytes)
	mut serial_buf := []u8{len: 4}
	binary.big_endian_put_u32_at(mut serial_buf, q.serial, 0)
	rdata << serial_buf
	// Refresh, Retry, Expire, Minimum (4 bytes each, can be 0)
	rdata << [u8(0), 0, 0, 0]  // Refresh
	rdata << [u8(0), 0, 0, 0]  // Retry
	rdata << [u8(0), 0, 0, 0]  // Expire
	rdata << [u8(0), 0, 0, 0]  // Minimum

	// RDLENGTH (2 bytes)
	buf << [u8(0), u8(rdata.len)]
	buf << rdata

	return buf
}

fn query_to_buf_ixfr_tcp(q Query) []u8 {
	dns_msg := query_to_buf_ixfr(q)
	mut buf := []u8{len: 2}
	binary.big_endian_put_u16_at(mut buf, u16(dns_msg.len), 0)
	buf << dns_msg
	return buf
}

fn query_tcp(q Query) !Response {
	mut conn := net.dial_tcp(q.resolver) or { return error('could not dial TCP: ${err}') }
	defer {
		conn.close() or {}
	}

	conn.write(query_to_buf_tcp(q)) or { return error('could not send TCP query') }

	// Read 2-byte length prefix
	mut len_buf := []u8{len: 2}
	conn.read(mut len_buf) or { return error('could not read length prefix') }
	msg_len := binary.big_endian_u16_at(len_buf, 0)

	// Read full DNS message (may require multiple reads)
	mut buf := []u8{}
	mut remaining := int(msg_len)
	for remaining > 0 {
		mut chunk := []u8{len: remaining}
		n := conn.read(mut chunk) or { return error('could not read DNS response') }
		buf << chunk[..n]
		remaining -= n
	}

	return parse_response(mut &buf, int(msg_len))
}

fn query_axfr(q Query) !Response {
	mut conn := net.dial_tcp(q.resolver) or { return error('could not dial TCP: ${err}') }
	defer {
		conn.close() or {}
	}

	conn.write(query_to_buf_tcp(q)) or { return error('could not send AXFR query') }

	mut all_answers := []Answer{}
	mut soa_count := 0

	for {
		// Read 2-byte length prefix
		mut len_buf := []u8{len: 2}
		conn.read(mut len_buf) or { break }
		msg_len := binary.big_endian_u16_at(len_buf, 0)
		if msg_len == 0 {
			break
		}

		// Read full DNS message
		mut buf := []u8{}
		mut remaining := int(msg_len)
		for remaining > 0 {
			mut chunk := []u8{len: remaining}
			n := conn.read(mut chunk) or { break }
			buf << chunk[..n]
			remaining -= n
		}

		// Parse and collect answers
		response := parse_response(mut &buf, int(msg_len))
		for answer in response.answers {
			all_answers << answer
			if answer.type == .soa {
				soa_count++
				if soa_count >= 2 {
					// Closing SOA received, transfer complete
					return Response{answers: all_answers}
				}
			}
		}
	}

	return Response{answers: all_answers}
}

fn query_ixfr(q Query) !Response {
	mut conn := net.dial_tcp(q.resolver) or { return error('could not dial TCP: ${err}') }
	defer {
		conn.close() or {}
	}

	conn.write(query_to_buf_ixfr_tcp(q)) or { return error('could not send IXFR query') }

	mut all_answers := []Answer{}
	mut soa_count := 0

	for {
		// Read 2-byte length prefix
		mut len_buf := []u8{len: 2}
		conn.read(mut len_buf) or { break }
		msg_len := binary.big_endian_u16_at(len_buf, 0)
		if msg_len == 0 {
			break
		}

		// Read full DNS message
		mut buf := []u8{}
		mut remaining := int(msg_len)
		for remaining > 0 {
			mut chunk := []u8{len: remaining}
			n := conn.read(mut chunk) or { break }
			buf << chunk[..n]
			remaining -= n
		}

		// Parse and collect answers
		response := parse_response(mut &buf, int(msg_len))
		for answer in response.answers {
			all_answers << answer
			if answer.type == .soa {
				soa_count++
				if soa_count >= 2 {
					// Closing SOA received, transfer complete
					return Response{answers: all_answers}
				}
			}
		}
	}

	return Response{answers: all_answers}
}

fn query_to_string(query Query) string {
	q := query.transaction_id.str() + query.flags.str()

	// @TODO: ?
	return q
}

fn str2dns(s string) []u8 {
	mut result := []u8{}
	tokens := s.split('.')

	for token in tokens {
		result << u8(token.len)
		result << token.bytes()
	}

	result << 0
	return result
}

pub fn query(q Query) !Response {
	// AXFR requires special handling (multiple messages)
	if q.type == .axfr {
		return query_axfr(q)
	}

	// IXFR requires SOA in authority section
	if q.type == .ixfr {
		return query_ixfr(q)
	}

	// If explicit TCP requested, use TCP directly
	if q.tcp {
		return query_tcp(q)
	}

	// Try UDP first
	mut buf := []u8{len: 512}

	mut conn := net.dial_udp(q.resolver) or { return error('could not dial UDP: ${err}') }
	defer {
		conn.close() or {}
	}

	conn.write(query_to_buf(q)) or { return error('could not send UDP query') }

	res, _ := conn.read(mut buf) or { return error('Cannot read from buffer') }

	// Check for truncation, fallback to TCP
	if is_truncated(buf) {
		return query_tcp(q)
	}

	return parse_response(mut &buf, res)
}

fn read_fixed_len(buf []u8, pos int, len int) (string) {
	mut s := ''

	// @TODO: Get rid of unsafe construct
	unsafe {
		s = buf[pos].vstring_literal_with_len(len)
	}

	return s
}


fn read_var_len(buf []u8, pos int) (string, int) {
	mut s := ''
	mut len := buf[pos]

	// @TODO: Get rid of unsafe construct
	unsafe {
		s = buf[pos + 1].vstring_literal_with_len(len)
	}

	return s, len
}

fn read_domain(buf []u8, start int) (string, int) {
	mut s := ''
	mut pos := start

	mut len := buf[pos]
	mut total_bytes := 0

	for {
		len = buf[pos]

		// Read until null termination
		if len == 0 {
			total_bytes = total_bytes + 1
			// Root domain (Null-MX) returns "." instead of empty string
			if s == '' {
				s = '.'
			} else {
				s = s.trim_right('.')
			}
			break
		}

		// Check for compression (top 2 bits set = 0xc0)
		if len >= 0xc0 {
			offset := int((u16(len & 0x3f) << 8) | u16(buf[pos + 1]))
			total_bytes = total_bytes + 2  // Compression pointer is 2 bytes
			// @TODO: get rid of unsafe construct
			unsafe {
				part, _ := read_domain(buf, offset)
				s = s + part
			}
			break
		}
		else {
			// @TODO: get rid of unsafe construct
			assert pos + 1 + len <= buf.len
			unsafe {
				s = s + buf[pos + 1].vstring_literal_with_len(len) + '.'
			}
			pos = pos + len + 1
			total_bytes = total_bytes + 1 + len
		}
	}

	return s, total_bytes
}

fn type_to_str(t Type) string {
	return match t {
		.a      { 'a' }
		.aaaa   { 'aaaa' }
		.axfr   { 'axfr' }
		.caa    { 'caa' }
		.cert   { 'cert' }
		.cname  { 'cname' }
		.dnskey { 'dnskey' }
		.ixfr   { 'ixfr' }
		.mx     { 'mx' }
		.ns     { 'ns' }
		.ptr    { 'ptr' }
		.spf    { 'spf' }
		.soa    { 'soa' }
		.srv    { 'srv' }
		.tlsa   { 'tlsa' }
		.txt    { 'txt' }
		.uri    { 'uri' }
		else    { 'unknown(${int(t)})' }
	}
}

pub fn str_to_type(t string) Type {
	return match t.to_lower() {
		'a'      { .a }
		'aaaa'   { .aaaa }
		'axfr'   { .axfr }
		'caa'    { .caa }
		'cert'   { .cert }
		'cname'  { .cname }
		'dnskey' { .dnskey }
		'ixfr'   { .ixfr }
		'mx'     { .mx }
		'ns'     { .ns }
		'ptr'    { .ptr }
		'soa'    { .soa }
		'spf'    { .spf }
		'srv'    { .srv }
		'tlsa'   { .tlsa }
		'txt'    { .txt }
		'uri'    { .uri }
		else     {
			eprintln('Unknown type(${t}), assuming a record')
			return .a
		}
	}
}

fn int_to_type(i int) Type {
	return match i {
		int(Type.a)      { .a }
		int(Type.aaaa)   { .aaaa }
		int(Type.axfr)   { .axfr }
		int(Type.caa)    { .caa }
		int(Type.cert)   { .cert }
		int(Type.cname)  { .cname }
		int(Type.dnskey) { .dnskey }
		int(Type.ixfr)   { .ixfr }
		int(Type.mx)     { .mx }
		int(Type.ns)     { .ns }
		int(Type.ptr)    { .ptr }
		int(Type.soa)    { .soa }
		int(Type.spf)    { .spf }
		int(Type.srv)    { .srv }
		int(Type.tlsa)   { .tlsa }
		int(Type.txt)    { .txt }
		int(Type.uri)    { .uri }
		else {
			eprintln('unsupported type ${i}')
			return .any  // Return 'any' for unsupported types
		}
	}
}

pub fn shorten_ipv6(input string) string {
	mut groups := input.split(':')

	for mut group in groups {
		group = group.trim_left('0')
		if group == '' {
			group = '0'
		}
	}

	mut output := groups.join(':')
	mut search := '0:0:0:0:0:0:0'
	len := output.len

	for _ in 1..7 {
		output = output.replace(search, '')
		if output.len < len {
			break
		}
		search = search.trim_string_right(':0')
	}

	return output.to_lower()
}

fn parse_response(mut buf []u8, bytes int) Response {
	mut answers := []Answer{}

	// --- Header ---

	// Disabled code because it is not read from <--
	// transaction_id := binary.big_endian_u16_at(buf, 0)
	// flags := binary.big_endian_u16_at(buf, 2)
	// -->

	num_questions := binary.big_endian_u16_at(buf, 4)
	num_answers := binary.big_endian_u16_at(buf, 6)

	assert num_questions <= 1  // AXFR responses may have 0 questions

	if num_answers ==  0 {
		println("No answers!")
		//return -1
	}

	// Disabled code because it is not read from <--
	// auth_rrs := binary.big_endian_u16_at(buf, 8)
	// additional_rrs := binary.big_endian_u16_at(buf, 10)
	// -->

	// --- Query ---

	_, domain_len := read_domain(buf, 12)

	// Disabled code because it is not read from <--
	// typ := binary.big_endian_u16_at(buf, 12 + domain_len)
	// t := int_to_type(typ)
	// class := binary.big_endian_u16_at(buf, 14 + domain_len)
	// -->

	mut rel_pos := 16 + domain_len

	// --- Answers ---

	for _ in 0..num_answers {
		a_domain, name_len := read_domain(buf, rel_pos)
		a_type_i := binary.big_endian_u16_at(buf, rel_pos + name_len)
		a_type := int_to_type(a_type_i)
		a_class := int_to_class(binary.big_endian_u16_at(buf, rel_pos + name_len + 2))
		ttl := binary.big_endian_u32_at(buf, rel_pos + name_len + 4)
		a_len := binary.big_endian_u16_at(buf, rel_pos + name_len + 8)
		mut record := ''
		data_offset := rel_pos + name_len + 10

		match a_type {

			.a {
				mut result := []string{}
				for item in buf[data_offset..data_offset+4] {
					result << "$item"
				}

				ipv4 := result.join('.')
				record = ipv4
			}

			.aaaa {
				mut result := []string{}
				for x in 0..16 {
					result << buf[data_offset + x].hex()

					if x < 15 && x % 2 == 1 {
						result << ':'
					}
				}

				ipv6 := result.join('')
				record = shorten_ipv6(ipv6)
			}

			.caa {
				caa_flags := buf[data_offset]
				tag, tag_len := read_var_len(buf, data_offset + 1)

				issue := read_fixed_len(buf, data_offset + 1 + tag_len + 1, a_len - tag_len - 2)
				record = '${caa_flags} ${tag} ${issue}'
			}

			.cert {
				cert_type := binary.big_endian_u16_at(buf, data_offset)
				key_tag := binary.big_endian_u16_at(buf, data_offset + 2)
				algorithm := buf[data_offset + 4]
				cert_data := read_fixed_len(buf, data_offset + 5, a_len - 5)
				cert_b64 := base64.encode(cert_data.bytes())
				record = '${cert_type} ${key_tag} ${algorithm} ${cert_b64}'
			}

			.cname {
				cname, _ := read_domain(buf, data_offset)
				record = cname
			}

			.mx {
				preference := binary.big_endian_u16_at(buf, data_offset)
				mx, _ := read_domain(buf, data_offset + 2)
				record = '${preference} ${mx}'
			}

			.ns {
				ns, _ := read_domain(buf, data_offset)
				record = ns
			}

			.ptr {
				ptr, _ := read_domain(buf, data_offset)
				record = ptr
			}

			.soa {
				primary_ns, ns_bytes := read_domain(buf, data_offset)
				email, email_bytes := read_domain(buf, data_offset + ns_bytes)
				base := data_offset + ns_bytes + email_bytes
				serial := binary.big_endian_u32_at(buf, base)
				refresh := binary.big_endian_u32_at(buf, base + 4)
				retry := binary.big_endian_u32_at(buf, base + 8)
				expire := binary.big_endian_u32_at(buf, base + 12)
				minimum := binary.big_endian_u32_at(buf, base + 16)
				record = '${primary_ns} ${email} ${serial} ${refresh} ${retry} ${expire} ${minimum}'
			}

			.srv {
                priority := binary.big_endian_u16_at(buf, data_offset)
                weight := binary.big_endian_u16_at(buf, data_offset + 2)
                port := binary.big_endian_u16_at(buf, data_offset + 4)
                target, _ := read_domain(buf, data_offset + 6)
                record = '${priority} ${weight} ${port} ${target}'
			}

			.tlsa {
				cert_usage := buf[data_offset]
				selector := buf[data_offset + 1]
				matching_type := buf[data_offset + 2]
				tlsa_hex := read_fixed_len(buf, data_offset + 3, 32)
				record = "${cert_usage} ${selector} ${matching_type} "
				for i in 0..32 {
					if i == 28 {
						record += ' '
					}
					record += tlsa_hex[i].hex().to_upper()
				}
			}

			.txt {
				mut txt_offset := data_offset
				mut txt_len_total := 0
				for {
					txt_len := buf[txt_offset]
					txt_len_total = txt_len_total + 1 + txt_len
					assert txt_offset + txt_len <= buf.len
					txt := read_fixed_len(buf, txt_offset + 1, txt_len)
					record = record + txt

					if txt_len_total < a_len {
						txt_offset = txt_offset + 1 + txt_len
					}
					else if txt_len_total == a_len {
						break
					}
					else {
						panic('txt_len_total > a_len (${txt_len_total})')
					}
				}
			}

			.dnskey {
				flags := binary.big_endian_u16_at(buf, data_offset)
				protocol := buf[data_offset + 2]
				algorithm := buf[data_offset + 3]
				pubkey_raw := read_fixed_len(buf, data_offset + 4, a_len - 4)
				pubkey_b64 := base64.encode(pubkey_raw.bytes())
				record = "${flags} ${protocol} ${algorithm} ${pubkey_b64}"
			}

			.uri {
				priority := binary.big_endian_u16_at(buf, data_offset)
				weight := binary.big_endian_u16_at(buf, data_offset + 2)
				target := read_fixed_len(buf, data_offset + 4, a_len - 4)
				record = '${priority} ${weight} ${target}'
			}

			else {
				print('No handler for type ')
				println(type_to_str(a_type))
			}
		}

		rel_pos = rel_pos + name_len + 10 + a_len

		answers << Answer{
			name: a_domain,
			type: a_type,
			class: a_class,
			ttl: ttl,
			record: record
		}
	}

	return Response{answers: answers}
}

