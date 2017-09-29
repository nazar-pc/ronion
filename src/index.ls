/**
 * @package   Ronion
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
/*
 * Implements version 0.1.0 of the specification
 */
async-eventer	= require('async-eventer')

module.exports = Ronion

const COMMAND_CREATE_REQUEST	= 1
const COMMAND_CREATE_RESPONSE	= 2
const COMMAND_EXTEND_REQUEST	= 3
const COMMAND_EXTEND_RESPONSE	= 4
const COMMAND_DESTROY			= 5
const COMMAND_DATA				= 6

# How much segments can be in pending state per one address
const MAX_PENDING_SEGMENTS		= 10

/**
 * @param {Uint8Array} array
 *
 * @return {number}
 */
function uint_array_to_number (array)
	array[0] * 256 + array[1]

/**
 * @param {number} number
 *
 * @return {Uint8Array}
 */
function number_to_uint_array (number)
	lsb	= number % 256
	msb	= (number - lsb) / 256
	Uint8Array.of(msb, lsb)

/**
 * @param {Uint8Array} packet
 *
 * @return {array} [version: number, segment_id: Uint8Array, packet_data: Uint8Array]
 */
function parse_packet (packet)
	# First byte is version, next 2 bytes are segment_id and the rest are packet data
	[packet[0], packet.subarray(1, 2), packet.subarray(3)]

/**
 * @param {Uint8Array} packet_data
 *
 * @return {array} [command: number, command_data: Uint8Array]
 */
function parse_packet_data (packet_data)
	# First byte is command, next 2 bytes are command data length as unsigned integer in big endian format
	command				= packet_data[0]
	command_data_length	= uint_array_to_number(packet_data.subarray(1, 3))
	[command, packet_data.slice(3, 3 + command_data_length)]

/**
 * @param {number}		packet_size
 * @param {number}		version
 * @param {Uint8Array}	segment_id
 * @param {Uint8Array}	packet_data
 *
 * @return {Uint8Array}
 */
function generate_packet (packet_size, version, segment_id, packet_data)
	new Uint8Array(packet_size)
		..set([version])
		..set(segment_id, 1)
		..set(packet_data, 3)

/**
 * @param {number}		command
 * @param {Uint8Array}	command_data
 * @param {number}		max_command_data_length
 *
 * @return {Uint8Array}
 */
function generate_packet_data (command, command_data, max_command_data_length)
	# First byte is command, next 2 bytes are command data length as unsigned integer in big endian format, next are command data and the rest are zeroes
	new Uint8Array(3 + max_command_data_length)
		..set(command)
		..set(number_to_uint_array(command_data_length), 1)
		..set(command_data, 3)

/**
 * @param {Uint8Array}	address
 * @param {Uint8Array}	segment_id
 *
 * @return {string}
 */
function compute_source_id (address, segment_id)
	address.join('') + segment_id.join('')

/**
 * @constructor
 *
 * @param {number}	version			0..255
 * @param {number}	packet_size
 * @param {number}	address_length
 * @param {number}	mac_length
 */
!function Ronion (version, packet_size, address_length, mac_length)
	if !(@ instanceof Ronion)
		return new Ronion(version, packet_size, address_length, mac_length)
	async-eventer.call(@)

	@_version							= version
	@_packet_size						= packet_size
	@_address_length					= address_length
	@_mac_length						= mac_length
	# Map of outgoing established segments (first nodes in routing path) to list of nodes in routing path
	@_outgoing_established_segments		= new Map
	# Set of incoming established segments (created upon CREATE_REQUEST from previous node)
	@_incoming_established_segments		= new Set
	# Map of segments that were created for some purposes to their data, but were not confirmed yet; up to 10 unconfirmed segments per address are stored
	@_pending_segments					= new Map
	# Map of addresses to pending segments for that address, complements `_pending_segments` for convenience
	@_pending_address_segments			= new Map
	# Map of segments on which extension has started to the address where routing path is going to be extended, but didn't receive extension confirmation yet
	@_pending_extensions				= new Map
	# Map of segments where data can come from to segment where data should be forwarded to if can't be decrypted, each mapping results in 2 elements, one for each direction
	@_segments_forwarding_mapping		= new Map

Ronion:: =
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
		[version, segment_id, packet_data]	= parse_packet(packet)
		# Do nothing the version is unsupported
		if version != @_version
			return
		source_id	= compute_source_id(address, segment_id)
		# If segment is not established then we don't use encryption yet
		source_id	= compute_source_id(address, segment_id)
		if @_outgoing_established_segments.has(source_id) || @_incoming_established_segments.has(source_id) || @_segments_forwarding_mapping.has(source_id)
			@_process_packet_data_encrypted(source_id, packet_data)
		else
			@_process_packet_data_plaintext(address, segment_id, packet_data)
	/**
	 * Must be called when new segment is established with node that has specified address (after sending CREATE_REQUEST and receiving CREATE_RESPONSE)
	 *
	 * @param {Uint8Array}	address
	 * @param {Uint8Array}	segment_id
	 */
	confirm_outgoing_segment_established : (address, segment_id) !->
		source_id	= compute_source_id(address, segment_id)
		@_outgoing_established_segments.set(source_id, [address])
		@_unmark_segment_as_pending(address, segment_id)
	/**
	 * Must be called when new segment is established with node that has specified address (after receiving CREATE_REQUEST and sending CREATE_RESPONSE)
	 *
	 * @param {Uint8Array}	address
	 * @param {Uint8Array}	segment_id
	 */
	confirm_incoming_segment_established : (address, segment_id) !->
		source_id	= compute_source_id(address, segment_id)
		@_incoming_established_segments.add(source_id)
		@_unmark_segment_as_pending(address, segment_id)
	/**
	 * Must be called when new segment is established with node that has specified address
	 *
	 * @param {Uint8Array}	address		Node at which to start routing path
	 * @param {Uint8Array}	segment_id	Same segment ID as in CREATE_REQUEST
	 */
	confirm_extended_path : (address, segment_id) !->
		source_id			= compute_source_id(address, segment_id)
		next_node_address	= @_pending_extensions.get(source_id)
		@_outgoing_established_segments.get(source_id).push(next_node_address)
		@_pending_extensions.delete(source_id)
	/**
	 * Must be called in order to create new routing path that starts with specified address and segment ID, sends CREATE_REQUEST
	 *
	 * @param {Uint8Array}	address			Node at which to start routing path
	 * @param {Uint8Array}	command_data
	 *
	 * @return {Uint8Array} segment_id Generated segment ID that can be later used for routing path extension
	 *
	 * @throws {RangeError}
	 */
	create_request : (address, command_data) ->
		if command_data.length > @get_max_command_data_length()
			throw new RangeError('Too much command data')
		segment_id	= @_generate_segment_id(address)
		packet		= @_generate_packet_plaintext(segment_id, COMMAND_CREATE_REQUEST, command_data)
		@fire('send', {address, packet})
		@_mark_segment_as_pending(address, segment_id)
		segment_id
	/**
	 * Must be called in order to respond to CREATE_RESPONSE
	 *
	 * @param {Uint8Array}	address			Node from which CREATE_REQUEST come from
	 * @param {Uint8Array}	segment_id		Same segment ID as in CREATE_REQUEST
	 * @param {Uint8Array}	command_data
	 *
	 * @throws {RangeError}
	 */
	create_response : (address, segment_id, command_data) !->
		if command_data.length > @get_max_command_data_length()
			throw new RangeError('Too much command data')
		packet	= @_generate_packet_plaintext(segment_id, COMMAND_CREATE_RESPONSE, command_data)
		@fire('send', {address, packet})
	/**
	 * Must be called in order to extend routing path that starts with specified address and segment ID by one more segment, sends EXTEND_REQUEST
	 *
	 * @param {Uint8Array}	address				Node at which routing path has started
	 * @param {Uint8Array}	segment_id			Same segment ID as returned by CREATE_REQUEST
	 * @param {Uint8Array}	next_node_address	Node to which routing path will be extended from current last node, will be prepended to `command_data`
	 * @param {Uint8Array}	command_data		Subtract address length from max command data length, since `next_node_address` will be prepended
	 *
	 * @throws {RangeError}
	 * @throws {ReferenceError}
	 */
	extend_request : (address, segment_id, next_node_address, command_data) !->
		source_id	= compute_source_id(address, segment_id)
		if !@_outgoing_established_segments.has(source_id)
			throw new ReferenceError('There is no such segment established')
		# Harder command data length limit, since we need to fit address there as well
		if command_data.length > (@get_max_command_data_length() - @_address_length)
			throw new RangeError('Too much command data')
		target_address		= @_outgoing_established_segments.get(source_id).slice(-1)[0]
		command_data_full	= new Uint8Array(next_node_address.length + command_data.length)
			..set(next_node_address)
			..set(command_data, next_node_address.length)
		@_generate_packet_encrypted(address, segment_id, target_address, COMMAND_EXTEND_REQUEST, command_data_full).then (packet) !~>
			@fire('send', {address, packet})
			@_pending_extensions.set(source_id, next_node_address)
	/**
	 * @param {Uint8Array}	address
	 * @param {Uint8Array}	segment_id
	 * @param {Uint8Array}	command_data
	 */
	_extend_response : (address, segment_id, command_data) !->
		@_generate_packet_encrypted(address, segment_id, address, COMMAND_EXTEND_RESPONSE, command_data).then (packet) !~>
			@fire('send', {address, packet})
	/**
	 * Must be called when it is needed to destroy last segment in routing path that starts with specified address and segment ID
	 *
	 * @param {Uint8Array}	address		Node at which routing path has started
	 * @param {Uint8Array}	segment_id	Same segment ID as returned by CREATE_REQUEST
	 */
	destroy : (address, segment_id) !~>
		source_id	= compute_source_id(address, segment_id)
		if !@_outgoing_established_segments.has(source_id)
			throw new ReferenceError('There is no such segment established')
		target_address	= @_outgoing_established_segments.get(source_id).pop()
		# Drop routing path entirely if no nodes left
		if !@_outgoing_established_segments.get(source_id).length
			@_outgoing_established_segments.delete(source_id)
		@_generate_packet_encrypted(address, segment_id, target_address, COMMAND_DESTROY, new Uint8Array).then (packet) !~>
			@fire('send', {address, packet})
	/**
	 * Must be called in order to send data to the node in routing path that starts with specified address and segment ID, sends DATA
	 *
	 * @param {Uint8Array}	address			Node at which routing path has started
	 * @param {Uint8Array}	segment_id		Same segment ID as returned by CREATE_REQUEST
	 * @param {Uint8Array}	target_address	Node to which data should be sent, in case of sending data back to the initiator is the same as `address`
	 * @param {Uint8Array}	command_data
	 *
	 * @throws {RangeError}
	 * @throws {ReferenceError}
	 */
	data : (address, segment_id, target_address, command_data) !->
		source_id	= compute_source_id(address, segment_id)
		if !@_outgoing_established_segments.has(source_id)
			throw new ReferenceError('There is no such segment established')
		if command_data.length > @get_max_command_data_length()
			throw new RangeError('Too much command data')
		@_generate_packet_encrypted(address, segment_id, target_address, COMMAND_DATA, command_data).then (packet) !~>
			@fire('send', {address, packet})
	/**
	 * Convenient method for knowing how much command data can be sent in one packet
	 *
	 * @return {number}
	 */
	get_max_command_data_length : ->
		# We use the same length limit both for encrypted and plaintext packets command data, since plaintext can be wrapped into encrypted one
		# Total packet size length - version - segment ID - command - command_data_length - MAC (of the packet data)
		@_packet_size - 1 - 2 - 1 - 2 - @_mac_length
	/**
	 * @param {Uint8Array}	address
	 * @param {Uint8Array}	segment_id
	 * @param {Uint8Array}	packet_data
	 */
	_process_packet_data_plaintext : (address, segment_id, packet_data) !->
		[command, command_data]	= parse_packet_data(packet_data)
		switch command
			case COMMAND_CREATE_REQUEST
				@_mark_segment_as_pending(address, segment_id)
				@fire('create_request', {address, segment_id, command_data})
			case COMMAND_CREATE_RESPONSE
				# Do nothing if we don't expect CREATE_RESPONSE
				if !@_pending_segments.has(source_id)
					return
				pending_segment_data	= @_pending_segments.get(source_id)
				if pending_segment_data.original_source
					# This is response from the node we've forwarded CREATE_REQUEST to, which originated from initiator, so let's wrap it in EXTEND_RESPONSE
					original_source	= pending_segment_data.original_source
					@_extend_response(original_source.address, original_source.segment_id, command_data)
				else
					# After at least one create_response event received routing path segment should be considered half-established and destroy() should be called
					# in order to drop half-established routing path segment
					@fire('create_response', {address, segment_id, command_data})
		@fire('send', {address, packet})
	/**
	 * @param {Uint8Array}	address
	 * @param {Uint8Array}	segment_id
	 * @param {Uint8Array}	packet_data_encrypted
	 */
	_process_packet_data_encrypted : (address, segment_id, packet_data_encrypted) !->
		source_id	= compute_source_id(address, segment_id)
		# When packets move in direction towards initiator, just forward without decryption attempt
		if !@_incoming_established_segments.has(source_id) && @_segments_forwarding_mapping.has(source_id)
			@_forward_packet_data(source_id, packet_data_encrypted)
			return
		@_decrypt(address, segment_id, packet_data_encrypted)
			.then (packet_data) !~>
				[command, command_data]	= parse_packet_data(packet_data)
				switch command
					case COMMAND_EXTEND_REQUEST
						try
							next_node_address				= command_data.subarray(0, @_address_length)
							segment_creation_request_data	= command_data.subarray(@_address_length)
							next_node_segment_id			= @create_request(next_node_address, segment_creation_request_data)
							original_source					= {address, segment_id}
							forward_to						= {next_node_address, next_node_segment_id}
							# Segment will be marked as pending in `create_request()` call, but here we override it with additional data
							# Segment to the next node is not added to forwarding until source sends data this node can't decrypt
							@_mark_segment_as_pending.set(address, segment_id, {forward_to})
							@_mark_segment_as_pending.set(next_node_address, next_node_segment_id, {original_source})
						catch e
							if !(e instanceof RangeError)
								throw e
							# Send empty CREATE_RESPONSE indicating that it is not possible to extend routing path
							@create_response(address, segment_id, new Uint8Array)
							return
					case COMMAND_EXTEND_RESPONSE
						if @_pending_extensions.has(source_id)
							@fire('extend_response', {address, segment_id, command_data})
					case COMMAND_DESTROY
						if @_incoming_established_segments.has(source_id)
							@_incoming_established_segments.delete(source_id)
							@_del_segments_forwarding_mapping(address, segment_id)
							@fire('destroy', {address, segment_id})
					case COMMAND_DATA
						@fire('data', {address, segment_id, command_data})
			.catch !~>
				if @_segments_forwarding_mapping.has(source_id)
					@_forward_packet_data(source_id, packet_data_encrypted)
				else if @_pending_segments.has(source_id)
					# Now we've got packet on incoming segment, which is pending at the same time
					# This can mean that segment was used to extend routing path to the next node (in which case there should be `forward_to`)
					pending_segment_data	= @_pending_segments.get(source_id)
					if pending_segment_data.forward_to
						# Since we can't decrypt the packet, this means that the extension succeeded and initiator sends encrypted messages to that node
						# We can now forwarding mapping for segments
						{next_node_address, next_node_segment_id}	= pending_segment_data.forward_to
						@_unmark_segment_as_pending(address, segment_id)
						@_unmark_segment_as_pending(next_node_address, next_node_segment_id)
						@_add_segments_forwarding_mapping(address, segment_id, next_node_address, next_node_segment_id)
						@_forward_packet_data(source_id, packet_data_encrypted)
	/**
	 * @param {string}		source_id
	 * @param {Uint8Array}	packet_data_encrypted
	 */
	_forward_packet_data : (source_id, packet_data_encrypted) !->
		[target_address, target_segment_id]	= @_segments_forwarding_mapping.get(source_id)
		packet								= generate_packet(@_packet_size, @_version, target_segment_id, packet_data_encrypted)
		@fire('send', {address : target_address, packet})
	/**
	 * @param {Uint8Array} address
	 *
	 * @return {Uint8Array}
	 *
	 * @throws {RangeError}
	 */
	_generate_segment_id : (address) ->
		for i from 0 til 2**16
			segment_id	= number_to_uint_array(i)
			source_id	= compute_source_id(address, segment_id)
			if !@_outgoing_established_segments.has(source_id) && !@_pending_segments.has(source_id) && !@_incoming_established_segments.has(source_id)
				return segment_id
		throw new RangeError('Out of possible segment IDs')
	/**
	 * @param {number}		packet_size
	 * @param {number}		version
	 * @param {Uint8Array}	segment_id
	 * @param {number}		command
	 * @param {Uint8Array}	command_data
	 *
	 * @return {Uint8Array}
	 */
	_generate_packet_plaintext : (segment_id, command, command_data) ->
		packet_data	= generate_packet_data(command, command_data, @get_max_command_data_length())
		generate_packet(@_packet_size, @_version, segment_id, packet_data)
	/**
	 * @param {Uint8Array}	address
	 * @param {Uint8Array}	segment_id
	 * @param {Uint8Array}	target_address
	 * @param {number}		command
	 * @param {Uint8Array}	command_data
	 *
	 * @return {Promise} Resolves with Uint8Array packet
	 */
	_generate_packet_encrypted : (address, segment_id, target_address, command, command_data) ->
		packet_data	= generate_packet_data(command, command_data, @get_max_command_data_length())
		@_encrypt(address, segment_id, address, packet_data).then (command_data_encrypted) ~>
			generate_packet(@_packet_size, @_version, segment_id, packet_data)
	/**
	 * @param {Uint8Array}	address1
	 * @param {Uint8Array}	segment_id1
	 * @param {Uint8Array}	address2
	 * @param {Uint8Array}	segment_id2
	 */
	_add_segments_forwarding_mapping : (address1, segment_id1, address2, segment_id2) !->
		# Drop any old mappings
		@_del_segments_forwarding_mapping(address1, segment_id1)
		@_del_segments_forwarding_mapping(address2, segment_id2)

		source_id1	= compute_source_id(address1, segment_id1)
		source_id2	= compute_source_id(address2, segment_id2)
		@_segments_forwarding_mapping.set(source_id1, [address2, segment_id2])
		@_segments_forwarding_mapping.set(source_id2, [address1, segment_id1])
	/**
	 * @param {Uint8Array}	address
	 * @param {Uint8Array}	segment_id
	 */
	_del_segments_forwarding_mapping : (address, segment_id) !->
		source_id1	= compute_source_id(address, segment_id)
		if @_segments_forwarding_mapping.has(source_id1)
			[address2, segment_id2]	= @_segments_forwarding_mapping.get(source_id1)
			source_id2				= compute_source_id(address2, segment_id2)
			@_segments_forwarding_mapping.delete(source_id1)
			@_segments_forwarding_mapping.delete(source_id2)
	/**
	 * @param {Uint8Array}	address
	 * @param {Uint8Array}	segment_id
	 * @param {object}		data
	 */
	_mark_segment_as_pending : (address, segment_id, data = {}) !->
		# Drop any old mark if it happens to exist
		@_unmark_segment_as_pending(address, segment_id)

		source_id		= compute_source_id(address, segment_id)
		address_string	= address.join('')
		@_pending_segments.set(source_id, data)

		if !@_pending_address_segments.has(address_string)
			@_pending_address_segments.set(address_string, [])
		pending_address_segments	= @_pending_address_segments.get(address_string)
		pending_address_segments.push(segment_id)
		if pending_address_segments.length > MAX_PENDING_SEGMENTS
			old_pending_segment_id	= pending_address_segments.shift()
			@_unmark_segment_as_pending(address, old_pending_segment_id)
	/**
	 * @param {Uint8Array}	address
	 * @param {Uint8Array}	segment_id
	 */
	_unmark_segment_as_pending : (address, segment_id) !->
		if !@_pending_segments.has(source_id)
			return
		@_pending_segments.delete(source_id)

		segment_id_string			= segment_id.join('')
		pending_address_segments	= @_pending_address_segments.get(address_string)
		for existing_segment_id, i in pending_address_segments
			if existing_segment_id.join('') == segment_id_string
				pending_address_segments.splice(i, 1)
				return
	/**
	 * @param {Uint8Array}	address			Node at which routing path has started
	 * @param {Uint8Array}	segment_id		Same segment ID as returned by CREATE_REQUEST
	 * @param {Uint8Array}	target_address	Address for which to encrypt (can be the same as address argument or any other node in routing path)
	 * @param {Uint8Array}	plaintext
	 *
	 * @return {Promise} Will resolve with Uint8Array ciphertext if encrypted successfully
	 */
	_encrypt : (address, segment_id, target_address, plaintext) ->
		data	= {address, segment_id, target_address, plaintext, ciphertext : null}
		promise	= @fire('encrypt', data).then ~>
			ciphertext	= data.ciphertext
			if !(ciphertext instanceof Uint8Array) || ciphertext.length != (plaintext.length + @_mac_length)
				throw new Error('Encryption failed')
			ciphertext
		promise.catch(->) # Just to avoid unhandled promise rejection
		promise
	/**
	 * @param {Uint8Array}	address		Node at which routing path has started
	 * @param {Uint8Array}	segment_id	Same segment ID as returned by CREATE_REQUEST
	 * @param {Uint8Array}	ciphertext
	 *
	 * @return {Promise} Will resolve with Uint8Array plaintext if decrypted successfully
	 */
	_decrypt : (address, segment_id, ciphertext) ->
		source_id	= compute_source_id(address, segment_id)
		if @_outgoing_established_segments.has(source_id)
			# If ciphertext comes from outgoing segment, it can be from any node in the routing path,
			# Let't try to decrypt as it comes from each node in routing path starting from the last one
			target_addresses	= @_outgoing_established_segments.get(source_id).slice().reverse()
		else
			# Otherwise it can only come from previous node, so let's try it
			target_addresses	= [address]
		promise	= Promise.reject()
		data	= {address, segment_id, target_addresses : null, ciphertext, plaintext : null}
		target_addresses.forEach (target_address) !~>
			promise	:= promise
				.catch ~>
					data.target_address	= target_address
					@fire('decrypt', data)
				.then ->
					plaintext	= data.plaintext
					if !(plaintext instanceof Uint8Array) || plaintext.length != (ciphertext.length - @_mac_length)
						throw new Error('Decryption failed')
					plaintext
		promise.catch(->) # Just to avoid unhandled promise rejection
		promise

Ronion:: = Object.assign(Object.create(async-eventer::), Ronion::)

Object.defineProperty(Ronion::, 'constructor', {enumerable: false, value: Ronion})
