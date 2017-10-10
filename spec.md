# Ronion anonymous routing protocol framework specification

Specification version: 0.3.2

Author: Nazar Mokrynskyi

License: Ronion anonymous routing protocol framework specification (this document) is hereby placed in the public domain

### Introduction
This document is a textual specification of the Ronion anonymous routing protocol framework.
The goal of this document is to give enough guidance to permit a complete and correct implementation of the protocol.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in IETF [RFC 2119](http://www.ietf.org/rfc/rfc2119.txt).

#### What Ronion is and what isn't
Ronion's primary goal is to provide a well defined, easy to follow and secure specification for anonymous routing that can be relied upon when building higher level protocols in order to reduce the number of decisions that need to be made.

The protocol framework is deliberately designed in a generic way, so that it would be possible to use it with different cryptographic algorithms, transport layers and nodes selection approaches.

This framework (in contrast to Tor, mix net) doesn't specify how exactly nodes are selected and even what nodes addresses are - those are application layer decisions.
It only specifies how communication SHOULD happen and provides basic building blocks for higher level protocols.
In fact, this framework can be used as the foundation for Tor-like routing or mix network implementations.

#### Glossary
* Initiator: the node that initiates communication
* Responder: the node with which initiator wants to communicate with
* Routing path: a sequence of nodes that form a path through which initiator and responder are connected and can anonymously send encrypted data
* Routing path segment: part of routing path between 2 adjacent nodes, on each node routing path segment is identified using routing path segment identifier and address of the node on the other end of the segment
* Packet: set of bytes to be transferred from one node to another
* Application: software that uses implementation of this protocol

#### Assumptions
The only assumption about encryption algorithm used is that authenticated encryption is used (application MUST specify MAC length in bytes).

The only assumption about transport layer is that it delivers data in the same order as the data were sent (think of TCP instead of UDP, no out-of-order delivery).

#### Goals
The goals of this protocol framework are:
* anonymizing the connection between initiator and responder so that nodes in routing path don't know who is initiator and who is responder
* anonymizing the connection between initiator and responder so that responder doesn't know who initiator is and doesn't know its address
* hiding exact number of intermediate nodes used from any node in routing path including responder as well as limited observer
* hiding exact size and contents of the transmitted data sent from initiator to responder and backwards from any of the node in routing path as well as global observer
* allow application to use its own encryption algorithm, transport layer and data structures of the messages

Ronion depends heavily on application's decisions and tries to stay away from enforcing implementation details as much as possible, while still providing easy to follow framework for building secure and anonymous communication.

#### Numbers
All numbers are unsigned integers in big endian format.

#### Address
Address format is defined by application and MUST have constant length.

Address is typically either IP:port combination or public key of the node.

#### Re-wrapping
Re-wrapping a process of non-authenticated encryption or decryption using synchronous stream cipher, which is basically applying bitwise XOR to one bit at a time. Wrapping and unwrapping are exactly the same bitwise XOR operations, so they will be often called re-wrapping for simplicity.

When initiator sends encrypted data to the last node in routing path it wraps (encrypts without authentication) encrypted data multiple times and each node in routing path unwraps (decrypts without authentication) it before encrypted data reach responder. When some node sends data to initiator, it will wrap encrypted data, each node in the routing path will also wrap encrypted data and initiator will eventually unwrap data necessary number of times.

Re-wrapping doesn't have any integrity check (non-authenticated) and relies on end-to-end authenticated encryption. The only purpose of re-wrapping is to hide encrypted data from limited observer that controls more than 1 node on the routing path (re-wrapped data will look differently on each segment of the routing path).

#### Encryption
`{}` means data are encrypted (as the result of consuming `CREATE_REQUEST` and `CREATE_RESPONSE` and establishing corresponding encryption keys) and current node is capable of encrypting and/or decrypting it.
MAC is assumed to be present after encrypted data, but not shown explicitly.

NOTE: data are always wrapped at least once after encryption and need to be unwrapped before decryption!

#### Data structure notation
`[]` is used to specify a distinct piece of raw data (encrypted if placed under `{}`).
The size of the data piece is specified in bytes after colon like this: `[data: 2]`, if no size specified, then data occupies the rest of available space.
Exact value can be specified after data piece size separated by coma: `[data: 2, 1]`.

#### Packet format
```
[version: 1][segment_id: 2][packet_data]
```

`[version]` encapsulates address format, crypto algorithms used, set of commands and other important details used on that connection, supplied by application.
Version is kept the same on each hop of the same routing path and never changes in the middle of the routing path.
`[segment_id]` is unique to each segment of the network, the response MUST always preserve `[segment_id]` of the request so that it is clear where to send it further.

#### Packet size
Total packet size is fixed and configured by application, padding with random bytes is used when needed as described in corresponding sections.

It is responsibility of the application to carefully count how many bytes can be sent in each particular command type with selected encryption algorithm and make sure data will fit into one packet (or split data into multiple packets if needed).

#### [zero_bytes_padding]
Is added at the end of the command data when needed (so that all packets always have configured size).

#### Commands
Commands explain what node MUST do with the packet it has received, supported commands are listed below.

Each command is represented by number from the range `1..255`.
The list of supported commands is given below, unused numbers are reserved for future versions of the specification:

| Command name    | Numeric value |
|-----------------|---------------|
| CREATE_REQUEST  | 1             |
| CREATE_RESPONSE | 2             |
| EXTEND_REQUEST  | 3             |
| EXTEND_RESPONSE | 4             |
| DESTROY         | 5             |
| DATA            | 6             |

### Routing path construction
Before routing path construction happens, application layer MUST select:
* encryption algorithm for end-to-end authenticated encryption
* stream cipher for re-wrapping
* a list of nodes (represented by their addresses) that will together form a routing path

Routing path construction is started by initiator with sending `CREATE_REQUEST` command(s) to the first node in routing path in order to create the first routing path segment and receives `CREATE_RESPONSE` command(s) back.

After last `CREATE_RESPONSE` received by initiator each side should have:
* A pair of re-wrapping stream ciphers with unique random initial data that will be used for messages re-wrapping
* A pair of unique objects for messages encryption and decryption

There will be 2 stream ciphers with their initial data and 2 encryption/decryption objects so that data can be sent by initiator and towards initiator independently (full-duplex).

Then initiator sends `EXTEND_REQUEST` command(s) to the first node in order to extend the routing path by one more segment to the second node and receives `EXTEND_RESPONSE` command(s) back.
Initiator keeps sending `EXTEND_REQUEST` commands to the last node in current routing path until last node in routing path is responder, at which point routing path is ready to send data back and forth.

`EXTEND_REQUEST` essentially encapsulates `CREATE_REQUEST` and `EXTEND_RESPONSE` encapsulates `CREATE_RESPONSE`, so eventually initiator will have unique pairs of stream ciphers for re-wrapping and encryption/decryption objects with each node in routing path.

### Routing path usage
When routing path is constructed, initiator can send data towards nodes in routing path and other nodes in routing path can send data towards initiator.

After encrypting data, sender applies re-wrapping using stream cipher for specific path direction (remember, we have 2 stream ciphers, one for each direction) and sends data to the next node in routing path.

When node receives encrypted data it applies re-wrapping to the data first, then tries to decrypt. If decryption fails - re-wrapped data are sent to the next node in routing path.

### Plain text commands
These commands are used prior to establishing routing path segments with specified `[segment_id]`, as soon as routing path segment is established plaintext commands MUST NOT be accepted.

#### CREATE_REQUEST
Is sent when creating segment of routing path is needed, can be send multiple times to the same node if multiple roundtrips are needed.

Request data:
```
[command: 1, 1][segment_creation_request_data_length: 2][segment_creation_request_data][zero_bytes_padding]
```

Request data handling:
* `[segment_creation_request_data]` is consumed by the node in order to generate keys for routing path segment creation
* `[segment_id]` is linked by protocol implementation with address of the node where `CREATE_REQUEST` came from, together `[segment_id]` and node address uniquely identify routing path segment
* responds to the previous node with `CREATE_RESPONSE` command

#### CREATE_RESPONSE
Is sent as an answer to `CREATE_REQUEST`, is sent exactly once in response to each `CREATE_REQUEST`.

Response data:
```
[command: 1, 2][segment_creation_response_data_length: 2][segment_creation_response_data][zero_bytes_padding]
```

Response data handling:
* if current node has initiated `CREATE_REQUEST` then `[segment_creation_response_data]` is consumed by the node in order to perform routing path segment creation
* if current node has not initiated `CREATE_REQUEST`, but instead it `EXTEND_REQUEST` command was sent by another node, `EXTEND_RESPONSE` is generated in response

### Encrypted commands
These commands are used after establishing routing path segment with specified `[segment_id]` and corresponding node address.

Each encrypted command request data follows following pattern:
```
{[command: 1][command_data_length: 2][command_data][zero_bytes_padding]}
```

#### EXTEND_REQUEST command
Is used in order to extend routing path one segment further, effectively generates `CREATE_REQUEST` to the next node, can be send multiple times to the same node if multiple roundtrips are needed.

If `[segment_id]` was previously extended to another node, that link between `[segment_id]` of the previous node and `[segment_id]` of the next node MUST be destroyed and new routing path extension MUST be performed.

Request data:
```
{[command: 1, 3][address_and_segment_creation_request_data_length: 2][next_node_address][segment_creation_request_data][zero_bytes_padding]}
```

Request data handling:
* decrypt command and command data length
* if command is `EXTEND_REQUEST` then send `CREATE_REQUEST` command with `[segment_creation_request_data]` command data to the `[next_node_address]` using newly generated `[segment_id]` for that segment
* `[segment_id]` of the previous node and `[segment_id]` of the next node MUST be linked together by protocol implementation for future data forwarding

`CREATE_REQUEST` request data being sent:
```
[command: 1, 1][segment_creation_request_data_length: 2][segment_creation_request_data][zero_bytes_padding]
```

#### EXTEND_RESPONSE command
Is used in order to extend routing path one segment further, effectively wraps `CREATE_RESPONSE` from next node and send it to the previous node, is sent exactly once in response to each `EXTEND_REQUEST`.

Response data:
```
{[command: 1, 4][segment_creation_response_data_length][segment_creation_response_data][zero_bytes_padding]}
```

Where `[segment_creation_response_data_length]` and `[segment_creation_response_data]` parts are taken from `CREATE_RESPONSE` data directly (which were sent in response to `CREATE_REQUEST`)`.

Response data handling:
* if `[segment_creation_response_data_length]` has value `0`, it means that routing path creation has failed (can happen if node can't extend the routing path, for instance, when node with specified address doesn't exist)

#### DESTROY command
Is used in order to destroy certain segment of the routing path. This command MUST only be sent by initiator and only to the last node in the routing path.

Request data:
```
{[command: 1, 5][length: 2, 0][zero_bytes_padding]}
```

No response is needed for this command, can be sent to nodes if unsure whether node is still alive and will actually receive the message.

After dropping the segment of the routing path, the last node left in the routing path can be used to again extend routing path to another node.

#### DATA command
Is used to actually transfer useful data between applications on different nodes.

`DATA` command doesn't differentiate request from response, it just send data, application layer SHOULD also take care of delivery confirmations if necessary, since this is not done by protocol either.

`DATA` command can be sent by:
* initiator towards any node in the routing path, including responder
* any node in the routing path, including responder, towards initiator

Request data:
```
{[command: 1, 6][data_length: 2][data][zero_bytes_padding]}
```

#### Data forwarding
Only works after `EXTEND_REQUEST` and `EXTEND_RESPONSE` happened before, so that node knows where to send data next.

Forwarding is happening when node can't decrypt the command after re-wrapping, which in turn means that the command was not intended for this node.
Also all of the data moving in direction from responder to initiator SHOULD be forwarded without command decryption attempt, since they are always intended for initiator.

Initiator upon receiving the data tries to decrypt data with keys that correspond to each node in routing path until it decrypts data successfully.
The order in which keys are selected is up to the application or implementation, but starting from the keys of the first node in the routing path and moving to the first node is a good idea, since it simplifies implementation (as unwrapping needs to be done after each decryption trial and this way it is easier to keep consistent state in stream cipher).

#### Dropping packets
If packets were forwarded through the whole routing path and the last node (either initiator or responder) still can't decrypt the packet, the packet is silently dropped.
If packet is decrypted successfully, but command is unknown, the packet is silently dropped.
Undecryptable or packets with non-existing command (just to stop data from moving to the next node) can be used to generate fake activity.

### Security and anonymity considerations for an application developer
Here is the list of things an application developer MUST consider in order to have secure and anonymous communication:
* application MUST always use authenticated encryption
* nodes MUST use separate unique temporary keys and initial data for stream ciphers for each segment and MUST NOT reuse them ever again
* application on any node MIGHT want to send fake packets, apply custom delays between sending packets and forward packets from independent `[segment_id]` in different order than they have come to the node in order to confuse an external observer

### Acknowledgements
This protocol framework is heavily inspired by [Tor](https://www.torproject.org/).

The address was intentionally not defined explicitly so that it can be anything, but the primary idea was to use this with DHT and use public key as both node ID in DHT and address in this protocol framework.

The crypto layer that was kept in mind throughout designing was `IK` handshake pattern from [The Noise Protocol Framework](https://noiseprotocol.org/).

Many thanks to Andrey Khavryuchenko for initial review and suggestions!
