/**
 * @package   Ronion
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */

/**
 * @record
 */
function Connection
	void
/**
 * @type {Uint8Array} Fixed-size address of remote peer, can be anything: IP:port, ID, etc.
 */
Connection::address
/**
 * Used in `data` event
 *
 * @callback ondata
 * @param {Uint8Array} data
 */
/**
 * Add an event handler
 *
 * @param {string}				event		Either `data` or `close`
 * @param {(ondata|Function)}	callback
 *
 * @return {Connection}
 */
Connection::on		= (event, callback) !->
/**
 * Remove event handler
 *
 * @param {string}		event		Either `data` or `close`
 * @param {Function}	callback
 *
 * @return {Connection}
 */
Connection::off		= (event, callback) !->
/**
 * @param {Uint8Array} data
 */
Connection::send	= (data) !->
Connection::close	= !->
