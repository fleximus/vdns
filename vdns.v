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
	aaaa   =  28
	dnskey =  48  // RFC4034: Resource Records for the DNS Security Extensions
	tlsa   =  52  // RFC6698: The DNS-Based Authentication of Named Entities (DANE)
	              //          Transport Layer Security (TLS) Protocol: TLSA
	spf    =  99
	tsig   = 250
	ixfr   = 251
	axfr   = 252
	any    = 255
	uri    = 256  // RFC7553: The Uniform Resource Identifier (URI) DNS Resource Record
	caa    = 257  // RFC6844: certificate authority authorization 
}

enum Class as u16 {
	@in   =   1  // RFC1035: the Internet
	cs    =   2
	ch    =   3  // RFC1035: the CHAOS class
	hs    =   4
	@none = 254  // RFC2136
	any   = 255  // RFC1035: ANY
}

fn int_to_class(i int) Class {
	return match i {
		int(Class.@in) { Class.@in }
		int(Class.cs) { Class.cs }
		int(Class.ch) { Class.ch }
		int(Class.hs) { Class.hs }
		int(Class.@none) { Class.@none }
		int(Class.any) { Class.any }
		else { panic('unknown class ${i}') }  // @TODO: Don't panic!
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
	reserved             // 10
	authentic_data       // 11
	checking_disabled    // 12
	b13                  // 13
	b14                  // 14
	b15                  // 15
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
	@type Type  = Type.a
	class Class = Class.@in
	resolver string
}

pub struct Answer {
pub:
	name string
	@type Type
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
	binary.big_endian_put_u16_at(mut buf, u16(q.@type), 14 + q.domain.len)
	binary.big_endian_put_u16_at(mut buf, u16(q.class), 16 + q.domain.len)

	return buf
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
	mut buf := []u8{len: 512}

	mut conn := net.dial_udp(q.resolver) or { panic('could not net.dial_udp: ${err}') }
	defer {
		conn.close() or {}
	}

	conn.write(query_to_buf(q)) or { panic('could not send data to UDP')}

	//mut buf := []u8{len: 512}
	res, _ := conn.read(mut buf) or { return error('Cannot read from buffer') }

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
		total_bytes = total_bytes + 1

		// Read until null termination
		if len == 0 {
			s = s.trim_right('.')
			break
		}
		
		// Check for compression
		if len == 0xc0 {
			offset := buf[pos + 1]
			// @TODO: get rid of unsafe construct
			unsafe {
				part, part_len := read_domain(buf, offset)
				s = s + part
				pos = pos + part_len
			}
			break
		}
		else {
			// @TODO: get rid of unsafe construct
			assert pos + 1 + len <= 512
			unsafe {
				s = s + buf[pos + 1].vstring_literal_with_len(len) + '.'
			}
			pos = pos + len + 1
			total_bytes = total_bytes + len
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
		.cname  { 'cname' }
		.dnskey { 'dnskey' }
		.ixfr   { 'ixfr' }
		.mx     { 'mx' }
		.ns     { 'ns' }
		.ptr    { 'ptr' }
		.spf    { 'spf' }
		.soa    { 'soa' }
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
		'cname'  { .cname }
		'dnskey' { .dnskey }
		'ixfr'   { .ixfr }
		'mx'     { .mx }
		'ns'     { .ns }
		'ptr'    { .ptr }
		'spf'    { .spf }
		'soa'    { .soa }
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
		int(Type.a)      { Type.a }
		int(Type.aaaa)   { Type.aaaa }
		int(Type.axfr)   { Type.axfr }
		int(Type.caa)    { Type.caa }
		int(Type.cname)  { Type.cname }
		int(Type.dnskey) { Type.dnskey }
		int(Type.mx)     { Type.mx }
		int(Type.ptr)    { Type.ptr }
		int(Type.tlsa)   { Type.tlsa }
		int(Type.txt)    { Type.txt }
		int(Type.uri)    { Type.uri }
		else {
			panic('unknown type ${i}') // @TODO: Don't panic!
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

	assert num_questions == 1

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
		a_domain, _ := read_domain(buf, rel_pos)
		a_type_i := binary.big_endian_u16_at(buf, rel_pos + 2)
		a_type := int_to_type(a_type_i)
		a_class := int_to_class(binary.big_endian_u16_at(buf, rel_pos + 4))
		ttl := binary.big_endian_u32_at(buf, rel_pos + 6)
		a_len := binary.big_endian_u16_at(buf, rel_pos + 10)
		mut record := ''

		match a_type {

			.a {
				mut result := []string{}
				for item in buf[rel_pos+12..rel_pos+16] {
					result << "$item"
				}

				ipv4 := result.join('.')
				record = ipv4
			}

			.aaaa {
				mut result := []string{}
				for x in 12..28 {
					result << buf[rel_pos + x].hex()

					if x < 27 && (x-1) % 2 == 0 {
						result << ':'
					}
				}

				ipv6 := result.join('')
				record = shorten_ipv6(ipv6)
			}

			.caa {
				caa_flags := buf[rel_pos + 12]
				tag, tag_len := read_var_len(buf, rel_pos + 13)

				issue := read_fixed_len(buf, rel_pos + 13 + tag_len + 1, a_len - tag_len - 2)
				record = '${caa_flags} ${tag} ${issue}'
			}

			.cname {
				cname, _ := read_domain(buf, rel_pos + 12)
				record = cname
			}

			.mx {
				preference := binary.big_endian_u16_at(buf, rel_pos + 12)
				mx, _ := read_domain(buf, rel_pos + 14)
				record = '${preference} ${mx}'
			}

			.ptr {
				ptr, _ := read_domain(buf, rel_pos + 12)
				record = ptr
			}

			.tlsa {
				cert_usage := buf[rel_pos + 12]
				selector := buf[rel_pos + 13]
				matching_type := buf[rel_pos + 14]
				tlsa_hex := read_fixed_len(buf, rel_pos + 15, 32)
				record = "${cert_usage} ${selector} ${matching_type} "
				for i in 0..32 {
					if i == 28 {
						record += ' '
					}
					record += tlsa_hex[i].hex().to_upper()
				}
			}

			.txt {
				mut txt_len_total := 0
				for {
					txt_len := buf[rel_pos + 12]
					txt_len_total = txt_len_total + 1 + txt_len
					assert rel_pos + txt_len <= 512
					txt := read_fixed_len(buf, rel_pos + 13, txt_len)
					record = record + txt

					if txt_len_total < a_len {
						rel_pos = rel_pos + 1 + txt_len
					}
					else if txt_len_total == a_len {
						rel_pos = rel_pos + 1 + txt_len + 12
						break
					}
					else {
						panic('txt_len_total > a_len (${txt_len_total})')
					}
				}
			}

			.dnskey {
				flags := binary.big_endian_u16_at(buf, rel_pos + 12)
				protocol := buf[rel_pos + 14]
				algorithm := buf[rel_pos + 15]
				pubkey_raw := read_fixed_len(buf, rel_pos + 16, a_len - 4)
				pubkey_b64 := base64.encode(pubkey_raw.bytes())
				record = "${flags} ${protocol} ${algorithm} ${pubkey_b64}"
			}

			.uri {
				priority := binary.big_endian_u16_at(buf, rel_pos + 12)
				weight := binary.big_endian_u16_at(buf, rel_pos + 14)
				target := read_fixed_len(buf, rel_pos + 16, a_len - 4)
				record = '${priority} ${weight} ${target}'
			}

			else {
				print('No handler for type ')
				println(type_to_str(a_type))
			}
		}

		if a_type != Type.txt {
			rel_pos = rel_pos + 12 + a_len
		}

		answers << Answer{
			name: a_domain,
			@type: a_type,
			class: a_class,
			ttl: ttl,
			record: record
		}
	}

	return Response{answers: answers}
}

