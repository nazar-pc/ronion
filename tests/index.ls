/**
 * @package   Ronion
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
crypto		= require('crypto')
lib			= require('..')
randombytes	= crypto.randomBytes
test		= require('tape')

const KEY_LENGTH	= 32
const MAC_LENGTH	= 16
encrypt_iv			= {}
wrap_iv				= {}

# Encryption
function encrypt (plaintext, key)
	iv							= randombytes(16)
	encrypt_iv[key.join('')]	= iv

	cipher		= crypto.createCipheriv('aes-256-gcm', key, iv)
	ciphertext	= cipher.update(plaintext)
	cipher.final()
	mac			= cipher.getAuthTag()
	encrypted	= new Uint8Array(ciphertext.length + mac.length)
		..set(ciphertext)
		..set(mac, ciphertext.length)
	Promise.resolve(encrypted)

# Decryption
function decrypt (encrypted, key)
	iv	= encrypt_iv[key.join('')]

	try
		decipher		= crypto.createDecipheriv('aes-256-gcm', key, iv)
		ciphertext		= encrypted.subarray(0, encrypted.length - MAC_LENGTH)
		mac				= encrypted.subarray(encrypted.length - MAC_LENGTH)
		decipher.setAuthTag(mac)
		plaintext		= decipher.update(ciphertext)
		decipher.final()
	catch
		return Promise.reject()
	delete encrypt_iv[key.join('')]
	Promise.resolve(plaintext)

# Wrapping
function wrap (plaintext, key)
	iv						= randombytes(16)
	wrap_iv[key.join('')]	= iv

	cipher		= crypto.createCipheriv('aes-256-ctr', key, iv)
	ciphertext	= cipher.update(plaintext)
	cipher.final()
	Promise.resolve(ciphertext)

# Unwrapping
function unwrap (ciphertext, key)
	iv	= wrap_iv[key.join('')]
	delete wrap_iv[key.join('')]

	decipher	= crypto.createDecipheriv('aes-256-ctr', key, iv)
	plaintext	= decipher.update(ciphertext)
	decipher.final()
	Promise.resolve(plaintext)

function compute_source_id (address, segment_id)
	address.join(',') + segment_id.join(',')

# Address of the node is simply its index in this array
nodes	= [
	new lib(1, 512, 1, MAC_LENGTH)
	new lib(1, 512, 1, MAC_LENGTH)
	new lib(1, 512, 1, MAC_LENGTH)
	new lib(1, 512, 1, MAC_LENGTH)
]

for let node, source_address in nodes
	node._address	= Uint8Array.of(source_address)
	node.on('send', (address, packet) !->
		nodes[address[0]].process_packet(node._address, packet)
	)
	node.on('create_request', (address, segment_id, command_data) !->
		if command_data.length == KEY_LENGTH
			node._in_segment_id						= segment_id
			source_id								= compute_source_id(address, segment_id)
			node[source_id]							=
				_remote_encryption_key	: command_data
				_local_encryption_key	: randombytes(KEY_LENGTH)
			node.create_response(address, segment_id, node[source_id]_local_encryption_key)
			node.confirm_incoming_segment_established(address, segment_id)
	)
	node.on('create_response', (address, segment_id, command_data) !->
		if command_data.length == KEY_LENGTH
			source_id								= compute_source_id(address, segment_id)
			node[source_id]_remote_encryption_key	= command_data
			node.confirm_outgoing_segment_established(address, segment_id)
	)
	node.on('extend_response', (address, segment_id, command_data) !->
		if command_data.length == KEY_LENGTH
			source_id										= compute_source_id(address, segment_id)
			target_address									= node._pending_extensions.get(source_id)
			target_source_id								= compute_source_id(target_address, segment_id)
			node[target_source_id]_remote_encryption_key	= command_data
			node.confirm_extended_path(address, segment_id)
	)
	node.on('destroy', (address, segment_id) !->
		source_id	= compute_source_id(address, segment_id)
		delete node[source_id]_remote_encryption_key
		delete node[source_id]_local_encryption_key
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
		{address, segment_id, target_address, unwrapped}	= data
		source_id											= compute_source_id(target_address, segment_id)
		# Separate keys should be used, but for tests we reuse the same keys (with different IVs though)
		wrap(unwrapped, node[source_id]_remote_encryption_key).then (data.wrapped) !->
	)
	node.on('unwrap', (data) ->
		{address, segment_id, target_address, wrapped}	= data
		source_id										= compute_source_id(target_address, segment_id)
		# Separate keys should be used, but for tests we reuse the same keys (with different IVs though)
		unwrap(wrapped, node[source_id]_local_encryption_key).then (data.unwrapped) !->
	)

test('Ronion', (t) !->
	t.plan(24)

	node_0	= nodes[0]
	node_1	= nodes[1]
	node_2	= nodes[2]
	node_3	= nodes[3]

	t.equal(node_0.get_max_command_data_length(), 490, 'Max command data length computed correctly')

	# Establish first segment
	node_1.once('create_request', (, , command_data) !->
		t.equal(command_data.join(''), key.join(''), 'Create request works')
	)
	node_0.once('create_response', (, , command_data) !->
		t.equal(command_data.length, KEY_LENGTH, 'Create response works')
		source_id_0	= compute_source_id(node_0._address, segment_id)
		source_id_1	= compute_source_id(node_1._address, node_1._in_segment_id)
		t.equal(node_0[source_id_1]_local_encryption_key.join(''), node_1[source_id_0]_remote_encryption_key.join(''), 'Encryption keys established #1')
		t.equal(node_1[source_id_0]_local_encryption_key.join(''), node_0[source_id_1]_remote_encryption_key.join(''), 'Encryption keys established #2')

		# Extend routing path by one more segment
		node_2.once('create_request', (, , command_data) !->
			t.equal(command_data.join(''), key.join(''), 'Extend request works and create request was called #1')
		)
		node_0.once('extend_response', (, , command_data) !->
			t.equal(command_data.length, KEY_LENGTH, 'Extend response works #1')
			source_id_0	= compute_source_id(node_1._address, segment_id)
			source_id_2	= compute_source_id(node_2._address, node_2._in_segment_id)
			t.equal(node_0[source_id_2]_local_encryption_key.join(''), node_2[source_id_0]_remote_encryption_key.join(''), 'Encryption keys established #3')
			t.equal(node_2[source_id_0]_local_encryption_key.join(''), node_0[source_id_2]_remote_encryption_key.join(''), 'Encryption keys established #4')

			# Extend routing path by one more segment
			node_3.once('create_request', (, , command_data) !->
				t.equal(command_data.join(''), key.join(''), 'Extend request works and create request was called #2')
			)
			node_0.once('extend_response', (, , command_data) !->
				t.equal(command_data.length, KEY_LENGTH, 'Extend response works #2')
				source_id_0	= compute_source_id(node_2._address, segment_id)
				source_id_3	= compute_source_id(node_3._address, node_3._in_segment_id)
				t.equal(node_0[source_id_3]_local_encryption_key.join(''), node_3[source_id_0]_remote_encryption_key.join(''), 'Encryption keys established #5')
				t.equal(node_3[source_id_0]_local_encryption_key.join(''), node_0[source_id_3]_remote_encryption_key.join(''), 'Encryption keys established #6')

				# Try sending data initiator to the first node in routing path
				data_0_to_1	= randombytes(30)
				node_1.once('data', (, , , , command_data) !->
					t.equal(command_data.join(''), data_0_to_1.join(''), 'Command data received fine #1')

					# Try sending data initiator to the third (and last) node in routing path
					data_0_to_3	= randombytes(30)
					node_3.once('data', (, , , , command_data) !->
						t.equal(command_data.join(''), data_0_to_3.join(''), 'Command data received fine #2')

						# Try sending data from the first node in routing path to initiator
						data_1_to_0	= randombytes(30)
						node_0.once('data', (, , , , command_data) !->
							t.equal(command_data.join(''), data_1_to_0.join(''), 'Command data received fine #3')

							# Try sending data from the second node in routing path to initiator
							data_2_to_0	= randombytes(30)
							node_0.once('data', (, , , , command_data) !->
								t.equal(command_data.join(''), data_2_to_0.join(''), 'Command data received fine #4')

								source_id	= compute_source_id(node_1._address, segment_id)
								t.equal(node_0._outgoing_established_segments.size, 1, 'Correct number of outgoing segments on node 0 before destroying')
								t.equal(node_0._outgoing_established_segments.get(source_id).length, 3, 'Correct route length on node 0 before destroying')
								t.equal(node_1._incoming_established_segments.size, 1, 'There is incoming segment on node 1 before destroying')
								t.equal(node_1._segments_forwarding_mapping.size, 2, 'There is forwarding segments mapping on node 1 before destroying')

								node_0.destroy(node_1._address, segment_id)
								t.equal(node_0._outgoing_established_segments.size, 0, 'Correct number of outgoing segments on node 0 after destroying')

								node_1.destroy(node_0._address, node_1._in_segment_id)
								t.equal(node_1._incoming_established_segments.size, 0, 'Correct number of incoming segments on node 1 after destroying')
								t.equal(node_1._segments_forwarding_mapping.size, 0, 'Correct number of forwarding mappings on node 1 after destroying')
							)
							node_2.data(node_1._address, node_2._in_segment_id, node_1._address, 0, data_2_to_0)
						)
						node_1.data(node_0._address, segment_id, node_0._address, 0, data_1_to_0)
					)
					node_0.data(node_1._address, segment_id, node_3._address, 0, data_0_to_3)
				)
				node_0.data(node_1._address, segment_id, node_1._address, 0, data_0_to_1)
			)

			key					= randombytes(KEY_LENGTH)
			source_id			= compute_source_id(node_3._address, segment_id)
			node_0[source_id]	= {_local_encryption_key : key}
			node_0.extend_request(node_1._address, segment_id, node_3._address, key)
		)
		key					= randombytes(KEY_LENGTH)
		source_id			= compute_source_id(node_2._address, segment_id)
		node_0[source_id]	= {_local_encryption_key : key}
		node_0.extend_request(node_1._address, segment_id, node_2._address, key)
	)
	key					= randombytes(KEY_LENGTH)
	segment_id			= node_0.create_request(node_1._address, key)
	source_id			= compute_source_id(node_1._address, segment_id)
	node_0[source_id]	= {_local_encryption_key : key}
)
