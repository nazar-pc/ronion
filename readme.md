# Ronion
Generic anonymous routing protocol framework agnostic to encryption algorithm and transport layer.

This repository contains high level design overview (design.md), specification for implementors (spec.md) and reference implementation.

WARNING: INSECURE UNTIL PROVEN THE OPPOSITE!!!

This protocol and reference implementation are intended to be secure, but until proper independent audit is conducted you shouldn't consider it to actually be secure and shouldn't use in production applications.

## Current status
Specification and design are not finalized yet, but seem good already.

Implementation API should be near stable and unlikely to change unless major spec changes are needed.

Still considered unstable, so be careful and make sure to report any issues you encounter. Project is covered with tests though to ensure it works as intended (see `tests` directory).

## Implementation API
Below if the list of public interfaces (constructors, methods and events) that are available.
Tests in `tests` directory can be used as an additional source of usage examples (not necessarily secure though!).

### Ronion(version : number, packet_size : number, address_length : number, mac_length : number, max_pending_segments = 10 : number)
Constructor used to create Ronion instance.

Will only process packets with specified version of specified size (will ignore others), expects fixed-size address and MAC length.

* `version` - Application-specific version 0..255
* `packet_size` - Packets will always have exactly this size
* `address_length` - Length of the node address
* `mac_length` - Length of the MAC that is added to ciphertext during encryption
* `max_pending_segments` - How much segments can be in pending state per one address (defaults to 10)

### Ronion.process_packet(address : Uint8Array, packet : Uint8Array)
Processes incoming packet.

* `address` - Address of the node where packet comes from
* `packet` - Packet itself

### Ronion.create_request(address : Uint8Array, command_data : Uint8Array) : Uint8Array
Generates packet with `CREATE_REQUEST` command in order to create the first segment in routing path.

This method can be called multiple times, in case of Noise IK handshake `command_data` will contain handshake message.

* `address` - Address of the first node in the routing path
* `command_data` - Data that are needed to be exchanged with `address` node in order to establish a segment

Method returns `segment_id` that together with `address` is used to identify the routing path.

### Ronion.confirm_outgoing_segment_established(address : Uint8Array, segment_id : Uint8Array)
Confirms that the first segment of routing path was established after sending `CREATE_REQUEST` and receiving `CREATE_RESPONSE`.

* `address` - Address used in `Ronion.create_request` method
* `segment_id` - Segment ID returned by `Ronion.create_request` method

### Ronion.create_response(address : Uint8Array, segment_id : Uint8Array, command_data : Uint8Array) : Uint8Array
Generates packet with `CREATE_RESPONSE` command as an answer to `CREATE_REQUEST` command.

This method is called exactly once in response to each `CREATE_REQUEST`.

* `address` - Address of the node where `CREATE_REQUEST` come from
* `segment_id` - Segment ID sent with `CREATE_REQUEST`
* `command_data` - Data that are needed to be exchanged with `address` node in order to establish a segment

### Ronion.confirm_incoming_segment_established(address : Uint8Array, segment_id : Uint8Array)
Confirms that the segment of routing path with `address` was established after receiving `CREATE_REQUEST` and sending `CREATE_RESPONSE`.

* `address` - Address used in `Ronion.create_response` method
* `segment_id` - Segment ID used in `Ronion.create_response` method

### Ronion.extend_request(address : Uint8Array, segment_id : Uint8Array, next_node_address : Uint8Array, command_data : Uint8Array)
Extends routing path by one more segment to `next_node_address` (generates packet with `EXTEND_REQUEST` command to the last node in routing path).

This method can be called multiple times, in case of Noise IK handshake `command_data` will contain handshake message.

* `address` - Address used in `Ronion.create_request` method
* `segment_id` - Segment ID returned by `Ronion.create_request` method
* `next_node_address` - Address of the node where routing path should be extended
* `command_data` - Data that are needed to be exchanged with `next_node_address` node in order to establish a segment (subtract address length from max command data length, since `next_node_address` will be prepended)

### Ronion.confirm_extended_path(address : Uint8Array, segment_id : Uint8Array)
Confirms that the routing path was extended by one more segment successfully.

* `address` - Address used in `Ronion.create_request` method
* `segment_id` - Segment ID returned by `Ronion.create_request` method

### Ronion.destroy(address : Uint8Array, segment_id : Uint8Array)
Destroys last segment of the routing path. Routing path can be re-extended to other node later (but take into account possible anonymity implications while doing so).

As soon as the first segment in routing path is destroyed, routing path itself is considered being destroyed.

* `address` - Address used in `Ronion.create_request` method
* `segment_id` - Segment ID returned by `Ronion.create_request` method

### Ronion.data(address : Uint8Array, segment_id : Uint8Array, target_address : Uint8Array, command_data : Uint8Array)
Send `command_data` data to the `target_address` node on routing path.

* `address` - Address used in `Ronion.create_request` method
* `segment_id` - Segment ID returned by `Ronion.create_request` method
* `target_address` - Address of the node in routing path which should receive data
* `command_data` - Data being sent

### Ronion.get_max_command_data_length() : number
Returns maximum number of bytes that `command_data` in other methods might contain.

### Ronion.on(event: string, callback: Function) : Ronion
Register event handler.

### Ronion.once(event: string, callback: Function) : Ronion
Register one-time event handler (just `on()` + `off()` under the hood).

### Ronion.off(event: string[, callback: Function]) : Ronion
Unregister event handler.

### Event: send
Payload object (all properties are `Uint8Array`):
```javascript
{address, packet}
```
Event is fired when `packet` needs to be sent to `address` node.

`false` or `Promise.reject()` can be returned from event handler in order to indicate non-fatal failure.

### Event: create_request
Payload object (all properties are `Uint8Array`):
```javascript
{address, segment_id, command_data}
```
Event is fired when `CREATE_REQUEST` command was received from `address` with segment ID `segment_id`. `command_data` contains the data that were specified during `Ronion.create_request` method call on `address`.

`false` or `Promise.reject()` can be returned from event handler in order to indicate non-fatal failure.

### Event: create_response
Payload object (all properties are `Uint8Array`):
```javascript
{address, segment_id, command_data}
```
Event is fired when `CREATE_RESPONSE` command was received from `address` with segment ID `segment_id`. `command_data` contains the data that were specified during `Ronion.create_response` method call on `address`.

`false` or `Promise.reject()` can be returned from event handler in order to indicate non-fatal failure.

### Event: extend_response
Payload object (all properties are `Uint8Array`):
```javascript
{address, segment_id, command_data}
```
Event is fired when `EXTEND_RESPONSE` command was received from `address` with segment ID `segment_id` as an answer to `Ronion.extend_request` method call. `command_data` contains the data that were specified by the node `next_node_address` from `Ronion.extend_request` method call.

`false` or `Promise.reject()` can be returned from event handler in order to indicate non-fatal failure.

### Event: destroy
Payload object (all properties are `Uint8Array`):
```javascript
{address, segment_id}
```
Event is fired when `DESTROY` command was received from `address` with segment ID `segment_id`.

`false` or `Promise.reject()` can be returned from event handler in order to indicate non-fatal failure.

### Event: data
Payload object (all properties are `Uint8Array`):
```javascript
{address, segment_id, command_data}
```
Event is fired when `DATA` command was received from `address` with segment ID `segment_id`. `command_data` contains data being sent to this node.

`false` or `Promise.reject()` can be returned from event handler in order to indicate non-fatal failure.

### Event: encrypt
Payload object (all properties are `Uint8Array`):
```javascript
{address, segment_id, target_address, plaintext, ciphertext : null}
```
Event is fired when `plaintext` from payload needs to be encrypted for node `target_address` on the routing path that starts with `address` and segment ID `segment_id`.

Ciphertext upon successful encryption should be placed into `ciphertext` property of the payload.

`false` or `Promise.reject()` can be returned from event handler in order to indicate non-fatal failure. Any errors thrown in even handler will be silently ignored.

### Event: decrypt
Payload object (all properties are `Uint8Array`):
```javascript
{address, segment_id, target_address, ciphertext, plaintext : null}
```
Event is fired when `ciphertext` from payload needs to be decrypted as if it comes from node `target_address` on the routing path that starts with `address` and segment ID `segment_id`.

Plaintext upon successful decryption should be placed into `plaintext` property of the payload.

`false` or `Promise.reject()` can be returned from event handler in order to indicate non-fatal failure. Any errors thrown in even handler will be silently ignored.

### Event: wrap
Payload object (all properties are `Uint8Array`):
```javascript
{address, segment_id, target_address, unwrapped, wrapped : null}
```
Event is fired when `unwrapped` from payload needs to be wrapped (encrypted without authentication) for node `target_address` on the routing path that starts with `address` and segment ID `segment_id`.

Wrapped ciphertext upon successful wrapping should be placed into `wrapped` property of the payload.

`false` or `Promise.reject()` can be returned from event handler in order to indicate non-fatal failure. Any errors thrown in even handler will be silently ignored.

### Event: unwrap
Payload object (all properties are `Uint8Array`):
```javascript
{address, segment_id, target_address, wrapped, unwrapped : null}
```
Event is fired when `wrapped` from payload needs to be unwrapped (decrypted without authentication) as if it comes from node `target_address` on the routing path that starts with `address` and segment ID `segment_id`.

Unwrapped ciphertext upon successful unwrapping should be placed into `unwrapped` property of the payload.

`false` or `Promise.reject()` can be returned from event handler in order to indicate non-fatal failure. Any errors thrown in even handler will be silently ignored.

## Contribution
Feel free to create issues and send pull requests (for big changes create an issue first and link it from the PR), they are highly appreciated!

## License
Implementation: MIT, see license.txt

Specification and design: public domain
