/**
 * @package   Ronion
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
/**
 * @param {Function} wrapper
 */
var define = function (wrapper) {};
/**
 * @param {string} module
 */
var require = function (module) {};
var exports = {};
var module = {};
module.exports	= {};

/**
 * @constructor
 */
function Eventer() {}
/**
 * @param {string}		event
 * @param {!Function}	callback
 *
 * @return {!Eventer}
 */
Eventer.prototype.on = function(event, callback) {};
/**
 * @param {string}		event
 * @param {!Function}	[callback]
 *
 * @return {!Eventer}
 */
Eventer.prototype.off = function(event, callback) {};
/**
 * @param {string}		event
 * @param {!Function}	callback
 *
 * @return {!Eventer}
 */
Eventer.prototype.once = function(event, callback) {};
/**
 * @param {string}	event
 * @param {...*}	param
 *
 * @return {!Promise}
 */
Eventer.prototype.fire = function(event, param) {};
