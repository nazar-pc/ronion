/**
 * @package   Ronion
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
module.exports = {Router, Circuit}

/**
 * @param {Uint8Array} array
 *
 * @return {string}
 */
function to_string (array)
	array.join('')

/**
 * @constructor
 */
!function Router
	if !(@ instanceof Router)
		return new Router
	@connections = {}

Router:: =
	/**
	 * @param {Connection} connection
	 */
	add_connection		: (connection) !->
		address					= to_string(connection.address)
		@connections[address]	= connection
			.on('data', ->
				# TODO: Handling received data
			)
			.on('close', @remove_connection.bind(@, connection))
	/**
	 * @param {(Connection|Uint8Array)} address_or_connection
	 */
	remove_connection	: (address_or_connection) !->
		if address_or_connection instanceof Uint8Array && to_string(address_or_connection) in @connections
			address = to_string(address_or_connection)
		else
			for key, value of @connections
				if value == address_or_connection
					address = key
			if !address
				throw new Error('Address or connection not found')
		delete @connections[address].onreceive
		delete @connections[address].onclose
		delete @connections[address]

Object.defineProperty(Router::, 'constructor', {enumerable: false, value: Router})

/**
 * @constructor
 *
 * @param {Connection}		entry_node_connection	Connection of the node where circuit starts
 * @param {Uint8Array[]}	hops_addresses			Addresses of nodes after entry_node_connection to extend circuit through
 * @param {number}			[max_hops]				Only useful if you want hide the actual number of hops from those who observe length of the packet
 */
!function Circuit (entry_node_connection, hops_addresses, max_hops = hops_addresses.length + 1)
	if !(@ instanceof Circuit)
		return new Circuit(entry_node_connection, hops_addresses, max_hops)
	if max_hops < (hops_addresses.length + 1)
		throw new Error('Incorrect max_hops, should be more')
	# TODO: Circuit creation

Circuit:: =
	destroy	: !->
		#TODO

Object.defineProperty(Circuit::, 'constructor', {enumerable: false, value: Circuit})
