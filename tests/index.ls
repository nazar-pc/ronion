/**
 * @package   Ronion
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
lib			= require('..')
randombytes	= require('crypto').randomBytes
test		= require('tape')

# Fake encryption
function encrypt (plaintext, [key])
	mac			= 0
	ciphertext	= plaintext.map (character) ->
		mac += character
		character .^. key
	mac			= mac % 256
	encrypted	= new Uint8Array(plaintext.length + 1)
		..set(ciphertext)
		..set([mac], ciphertext.length)
	Promise.resolve(encrypted)
# Fake decryption
function decrypt (encrypted, [key])
	mac			= 0
	plaintext	= encrypted.subarray(0, encrypted.length - 1).map (character) ->
		character	= character .^. key
		mac += character
		character
	mac			= mac % 256
	if mac != encrypted[encrypted.length - 1]
		Promise.reject()
	else
		Promise.resolve(plaintext)
# Fake keys generator
function generate_key
	do
		key	= randombytes(1)
	while key[0] == 0
	key

function compute_source_id (address, segment_id)
	address.join('') + segment_id.join('')

# Address of the node is simply its index in this array
nodes	= [
	new lib(1, 512, 1, 1)
	new lib(1, 512, 1, 1)
	new lib(1, 512, 1, 1)
]

var received_data

for let node, source_address in nodes
	node._address	= Uint8Array.of(source_address)
	node.on('send', ({address, packet}) !->
		nodes[address].process_packet(node._address, packet)
	)
	node.on('create_request', ({address, segment_id, command_data}) !->
		if command_data.length == 1
			node._in_segment_id						= segment_id
			source_id								= compute_source_id(address, segment_id)
			node[source_id]							=
				_remote_encryption_key	: command_data
				_local_encryption_key	: generate_key()
			node.create_response(address, segment_id, node[source_id]_local_encryption_key)
			node.confirm_incoming_segment_established(address, segment_id)
	)
	node.on('create_response', ({address, segment_id, command_data}) !->
		if command_data.length == 1
			source_id								= compute_source_id(address, segment_id)
			node[source_id]_remote_encryption_key	= command_data
			node.confirm_outgoing_segment_established(address, segment_id)
	)
	node.on('extend_response', ({address, segment_id, command_data}) !->
		if command_data.length == 1
			source_id										= compute_source_id(address, segment_id)
			target_address									= node._pending_extensions.get(source_id)
			target_source_id								= compute_source_id(target_address, segment_id)
			node[target_source_id]_remote_encryption_key	= command_data
			node.confirm_extended_path(address, segment_id)
	)
	node.on('destroy', ({address, segment_id}) !->
		source_id	= compute_source_id(address, segment_id)
		delete node[source_id]_remote_encryption_key
		delete node[source_id]_local_encryption_key
	)
	node.on('data', ({address, segment_id, command_data}) !->
		received_data	:= command_data
	)
	node.on('encrypt', (data) ->
		{address, segment_id, target_address, plaintext}	= data
		source_id											= compute_source_id(target_address, segment_id)
		encrypt(plaintext, node[source_id]_remote_encryption_key).then (data.ciphertext) !->
	)
	node.on('decrypt', (data) ->
		{address, segment_id, target_address, ciphertext}	= data
		source_id											= compute_source_id(target_address, segment_id)
		decrypt(ciphertext, node[source_id]_local_encryption_key).then (data.plaintext) !->
	)
	node.on('wrap', (data) ->
		# TODO: actual unwrapping
		data.wrapped	= data.unwrapped.slice()
	)
	node.on('unwrap', (data) ->
		# TODO: actual wrapping
		data.unwrapped	= data.wrapped.slice()
	)

test('Ronion', (t) !->

	t.equal(nodes[0].get_max_command_data_length(), 505, 'Max command data length computed correctly')

	node_0	= nodes[0]
	node_1	= nodes[1]
	node_2	= nodes[2]

	t.test('Create routing path (first segment)' (t) !->
		t.plan(25)

		# Establish first segment
		node_1.once('create_request', ({command_data}) !->
			t.equal(command_data.join(''), key.join(''), 'Create request works')
		)
		node_0.once('create_response', ({command_data}) !->
			t.equal(command_data.length, 1, 'Create response works')
			source_id_0	= compute_source_id(node_0._address, segment_id)
			source_id_1	= compute_source_id(node_1._address, node_1._in_segment_id)
			t.equal(node_0[source_id_1]_local_encryption_key.join(''), node_1[source_id_0]_remote_encryption_key.join(''), 'Encryption keys established #1')
			t.equal(node_1[source_id_0]_local_encryption_key.join(''), node_0[source_id_1]_remote_encryption_key.join(''), 'Encryption keys established #2')

			# Extend routing path by one more segment
			node_2.once('create_request', ({command_data}) !->
				t.equal(command_data.join(''), key.join(''), 'Extend request works and create request was called')
			)
			node_0.once('extend_response', ({command_data}) !->
				t.equal(command_data.length, 1, 'Extend response works')
				source_id_0	= compute_source_id(node_1._address, segment_id)
				source_id_2	= compute_source_id(node_2._address, node_2._in_segment_id)
				t.equal(node_0[source_id_2]_local_encryption_key.join(''), node_2[source_id_0]_remote_encryption_key.join(''), 'Encryption keys established #3')
				t.equal(node_2[source_id_0]_local_encryption_key.join(''), node_0[source_id_2]_remote_encryption_key.join(''), 'Encryption keys established #4')

				# Try sending data initiator to the first node in routing path
				data_0_to_1	= randombytes(30)
				node_1.once('data', ({command_data}) !->
					t.equal(command_data.join(''), data_0_to_1.join(''), 'Command data received fine #1')

					# Try sending data initiator to the second (and last) node in routing path
					data_0_to_2	= randombytes(30)
					node_2.once('data', ({command_data}) !->
						t.equal(command_data.join(''), data_0_to_2.join(''), 'Command data received fine #2')

						# Try sending data from the first node in routing path to initiator
						data_1_to_0	= randombytes(30)
						node_0.once('data', ({command_data}) !->
							t.equal(command_data.join(''), data_1_to_0.join(''), 'Command data received fine #3')

							# Try sending data from the second node in routing path to initiator
							data_2_to_0	= randombytes(30)
							node_0.once('data', ({command_data}) !->
								t.equal(command_data.join(''), data_2_to_0.join(''), 'Command data received fine #4')

								source_id	= compute_source_id(node_1._address, segment_id)
								t.equal(node_0._outgoing_established_segments.size, 1, 'Correct number of routes before destroying')
								t.equal(node_0._outgoing_established_segments.get(source_id).length, 2, 'Correct route length before destroying')
								t.equal(node_1._incoming_established_segments.size, 1, 'There is incoming segment on node 1 before destroying')
								t.equal(node_1._segments_forwarding_mapping.size, 2, 'There is forwarding segments mapping on node 1 before destroying')
								t.equal(node_2._incoming_established_segments.size, 1, 'There is incoming segment on node 2 before destroying')

								node_2.once('destroy', !->
									t.equal(node_0._outgoing_established_segments.size, 1, 'Correct number of routes after first destroying')
									t.equal(node_0._outgoing_established_segments.get(source_id).length, 1, 'Correct route length after first destroying')
									t.equal(node_1._incoming_established_segments.size, 1, 'There is incoming segment on node 1 after first destroying')
									t.equal(node_1._segments_forwarding_mapping.size, 2, 'There is still forwarding segments mapping on node 1 after first destroying')
									t.equal(node_2._incoming_established_segments.size, 0, 'There is no incoming segment on node 2 after first destroying')

									node_1.once('destroy', !->
										t.equal(node_0._outgoing_established_segments.size, 0, 'No routes after second destroying')
										t.equal(node_1._incoming_established_segments.size, 0, 'There is no incoming segment on node 1 after second destroying')
										t.equal(node_1._segments_forwarding_mapping.size, 0, 'There is no forwarding segments mapping on node 1 after first destroying')
									)
									node_0.destroy(node_1._address, segment_id)
								)
								node_0.destroy(node_1._address, segment_id)
							)
							node_2.data(node_1._address, node_2._in_segment_id, node_1._address, data_2_to_0)
						)
						node_1.data(node_0._address, segment_id, node_0._address, data_1_to_0)
					)
					node_0.data(node_1._address, segment_id, node_2._address, data_0_to_2)
				)
				node_0.data(node_1._address, segment_id, node_1._address, data_0_to_1)
			)
			key					= generate_key()
			source_id			= compute_source_id(node_2._address, segment_id)
			node_0[source_id]	= {_local_encryption_key : key}
			node_0.extend_request(node_1._address, segment_id, node_2._address, key)
		)
		key					= generate_key()
		segment_id			= node_0.create_request(node_1._address, key)
		source_id			= compute_source_id(node_1._address, segment_id)
		node_0[source_id]	= {_local_encryption_key : key}

		# TODO: the rest
	)


	t.end()
)
