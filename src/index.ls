/**
 * @package   Ronion
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
async-eventer	= require('async-eventer')
randombytes		= require('randombytes')

module.exports = {Router/*, Circuit*/}

const COMMAND_CREATE_REQUEST	= 1
const COMMAND_CREATE_RESPONSE	= 2
const COMMAND_EXTEND_REQUEST	= 3
const COMMAND_EXTEND_RESPONSE	= 4
const COMMAND_DESTROY			= 5
const COMMAND_DATA				= 6

/**
 * @param {Uint8Array} array
 *
 * @return {string}
 */
function to_string (array)
	array.join('')

/**
 * @param {Uint8Array} packet
 *
 * @return {array} [version: number, segment_id: Uint8Array]
 */
function parse_packet_header (packet)
	# First byte is version, next 2 bytes are segment_id
	[packet[0], packet.subarray(1, 2)]

/**
 * @param {Uint8Array} packet_data
 *
 * @return {number[]} [command, command_data_length]
 */
function parse_packet_data_header (packet_data)
	# First byte is command, next 2 bytes are command data length as unsigned integer in big endian format
	[packet_data[0], packet_data[0] * 256 + packet_data[1]]

/**
 * @param {Uint8Array} packet_data
 *
 * @return {array} [command: number, command_data: Uint8Array]
 */
function parse_packet_data_plaintext (packet_data)
	[command, command_data_length]	= parse_packet_data_header(packet_data)
	[command, packet_data.slice(3, 3 + command_data_length)]

/**
 * @param {number}		packet_size
 * @param {number}		version
 * @param {Uint8Array}	segment_id
 * @param {number}		command
 * @param {Uint8Array}	command_data
 *
 * @return {Uint8Array}
 */
function generate_packet_plaintext (packet_size, version, segment_id, command, command_data)
	packet_data_header	= generate_packet_data_header(command, command_data.length)
	packet	= new Uint8Array(packet_size)
		..set([version])
		..set(segment_id, 1)
		..set(packet_data_header, 3)
		..set(command_data, 6)
	bytes_written				= 6 + command_data.length
	random_bytes_padding_length	= packet_size - bytes_written
	if random_bytes_padding_length
		packet.set(randombytes(random_bytes_padding_length), bytes_written)
	packet

/**
 * @param {number}	command
 * @param {number}	command_data_length
 *
 * @return {Uint8Array}
 */
function generate_packet_data_header (command, command_data_length)
	# First byte is command, next 2 bytes are command data length as unsigned integer in big endian format
	lsb	= command_data_length % 256
	msb	= (command_data_length - lsb) / 256
	Uint8Array.of(command, msb, lsb)

/**
 * @param {Uint8Array}	address
 * @param {Uint8Array}	segment_id
 *
 * @return {string}
 */
function compute_source_id (address, segment_id)
	to_string(address) + to_string(segment_id)

/**
 * @constructor
 *
 * @param {number}	version			0..255
 * @param {number}	packet_size
 * @param {number}	address_length
 * @param {number}	mac_length
 */
!function Router (version, packet_size, address_length, mac_length)
	if !(@ instanceof Router)
		return new Router(version, packet_size, address_length, mac_length)
	async-eventer.call(@)

	@_version				= version
	@_packet_size			= packet_size
	@_address_length		= address_length
	@_mac_length			= mac_length
	@_established_segments	= new Set

Router:: =
	/**
	 * Must be called when new packet appear
	 *
	 * @param {Uint8Array}	address	Address (in application-specific format) where packet came from
	 * @param {Uint8Array}	packet	Packet
	 */
	process_packet : (address, packet) !->
		# Do nothing if packet or its size is incorrect
		if packet.length != @_packet_size
			return
		[version, segment_id]	= parse_packet_header(packet)
		# Do nothing the version is unsupported
		if version != @_version
			return
		source_id	= compute_source_id(address, segment_id)
		packet_data	= packet.subarray(3)
		# If segment is not established then we don't use encryption yet
		if !@_established_segments.has(source_id)
			@_process_packet_data_plaintext(address, segment_id, packet_data)
		else
			@_process_packet_data_encrypted(source_id, packet_data)
	/**
	 * Must be called when new segment is established with node that has specified address
	 *
	 * @param {Uint8Array}	address
	 * @param {Uint8Array}	segment_id
	 */
	confirm_established_segment : (address, segment_id) !->
		source_id	= compute_source_id(address, segment_id)
		@_established_segments.add(source_id)
	/**
	 * Must be called in order to start new routing path, sends CREATE_REQUEST
	 *
	 * @param {Uint8Array}	address		Node at which to start routing path
	 * @param {Uint8Array}	segment_id	Unique segment ID for specified address
	 * @param {Uint8Array}	data
	 */
	create_request : (address, segment_id, data) !->
		packet	= generate_packet_plaintext(@_packet_size, @_version, segment_id, COMMAND_CREATE_REQUEST, data)
		@fire('send', {address, packet})
	/**
	 * Must be called in order to respond to CREATE_RESPONSE
	 *
	 * @param {Uint8Array}	address		Node from which CREATE_REQUEST come from
	 * @param {Uint8Array}	segment_id	Same segment ID as in CREATE_REQUEST
	 * @param {Uint8Array}	data
	 */
	create_response : (address, segment_id, data) !->
		packet	= generate_packet_plaintext(@_packet_size, @_version, segment_id, COMMAND_CREATE_RESPONSE, data)
		@fire('send', {address, packet})
	/**
	 * @param {Uint8Array}	address
	 * @param {Uint8Array}	segment_id
	 * @param {Uint8Array}	packet_data
	 */
	_process_packet_data_plaintext : (address, segment_id, packet_data) !->
		[command, data]	= parse_packet_data_plaintext(packet_data)
		switch command
			case COMMAND_CREATE_REQUEST
				@fire('create_request', {address, segment_id, data})
			case COMMAND_CREATE_RESPONSE
				@fire('create_response', {address, segment_id, data})
	/**
	 * @param {string}		source_id
	 * @param {Uint8Array}	packet_data
	 */
	_process_packet_data_encrypted : (source_id, packet_data) !->
		# TODO: everything

Router:: = Object.assign(Object.create(async-eventer::), Router::)

Object.defineProperty(Router::, 'constructor', {enumerable: false, value: Router})

#/**
# * @constructor
# *
# * @param {Connection}		entry_node_connection	Connection of the node where circuit starts
# * @param {Uint8Array[]}	hops_addresses			Addresses of nodes after entry_node_connection to extend circuit through
# * @param {number}			[max_hops]				Only useful if you want hide the actual number of hops from those who observe length of the packet
# */
#!function Circuit (entry_node_connection, hops_addresses, max_hops = hops_addresses.length + 1)
#	if !(@ instanceof Circuit)
#		return new Circuit(entry_node_connection, hops_addresses, max_hops)
#	if max_hops < (hops_addresses.length + 1)
#		throw new Error('Incorrect max_hops, should be more')
#	# TODO: Circuit creation
#
#Circuit:: =
#	destroy	: !->
#		#TODO
#
#Object.defineProperty(Circuit::, 'constructor', {enumerable: false, value: Circuit})
