/**
 * @package   Ronion
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
async-eventer	= require('async-eventer')

module.exports = {Router/*, Circuit*/}

const COMMAND_CREATE_REQUEST	= 1
const COMMAND_CREATE_RESPONSE	= 2
const COMMAND_EXTEND_REQUEST	= 3
const COMMAND_EXTEND_RESPONSE	= 4
const COMMAND_DESTROY			= 5
const COMMAND_DATA				= 6
const COMMANDS_PLAINTEXT		= new Set([COMMAND_CREATE_REQUEST, COMMAND_CREATE_RESPONSE])
const COMMANDS_ENCRYPTED		= new Set([COMMAND_EXTEND_REQUEST, COMMAND_EXTEND_RESPONSE, COMMAND_DESTROY, COMMAND_DATA])

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
 * @return {array} [version: number, path_id: Uint8Array]
 */
function parse_packet_header (packet)
	# First byte is version, next 2 bytes are path_id
	[packet[0], packet.subarray(1, 2)]

/**
 * @param {Uint8Array} packet_data
 *
 * @return {number[]} [command, command_data_length]
 */
function parse_packet_data_header (packet_data)
	# First byte is command, next 2 bytes are unsigned integer in big endian format
	[packet_data[0], packet_data[0]*256 + packet_data[1]]

/**
 * @param {Uint8Array} packet_data
 *
 * @return {array} [command: number, command_data: Uint8Array]
 */
function parse_packet_data_plaintext (packet_data)
	[command, command_data_length]	= parse_packet_data_header(packet_data)
	[command, packet_data.slice(3, 3 + command_data_length)]

/**
 * @constructor
 */
!function Router (version, packet_size, address_length, mac_length)
	if !(@ instanceof Router)
		return new Router(version, packet_size, address_length, mac_length)
	async-eventer.call(@)

	@_version			= version
	@_packet_size		= packet_size
	@_address_length	= address_length
	@_mac_length		= mac_length
	@_established_paths	= new Set

Router:: =
	/**
	 * @param {Uint8Array}	source_address	Address (in application-specific format) where packet came from
	 * @param {Uint8Array}	packet			Packet
	 */
	process_packet : (source_address, packet) !->
		# Do nothing if packet size is incorrect
		if packet.length != @_packet_size
			return
		[version, path_id]	= parse_packet_header(packet)
		# Do nothing the version is unsupported
		if version != @_version
			return
		source_id	= to_string(source_address) + to_string(path_id)
		packet_data	= packet.subarray(3)
		# If path is not established then we don't use encryption yet
		if !@_established_paths.has(source_id)
			@_process_packet_data_plaintext(source_id, packet_data)
		else
			@_process_packet_data_encrypted(source_id, packet_data)
	/**
	 * @param {string}		source_id
	 * @param {Uint8Array}	packet_data
	 */
	_process_packet_data_plaintext : (source_id, packet_data) !->
		[command, command_data]	= parse_packet_data_plaintext(packet_data)
		# Do nothing if command is unknown or there is no data
		if !COMMANDS_PLAINTEXT.has(command) && !command_data.length
			return
		# TODO: handle data
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
