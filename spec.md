Ronion v0.0.1

### Introduction
This document is a textual specification of the Ronion anonymous routing protocol framework.
The goal of this document is to give enough guidance to permit a complete and correct implementation of the protocol.

The only assumption about encryption algorithm used is that authenticated encryption is used (application should specify MAC length in bytes).

The only assumption about transport layer used is that it delivers data in the same order as the data were sent (like in TCP).

#### Glossary
Initiator: the node that initiates communication.
Responder: the node with which initiator wants to communicate with.
Routing path: a sequence of nodes, represented by their addresses, that form a path through which initiator and responder are connected.
Packet: set of bytes to be transferred from one node to another.

#### Numbers
All numbers are unsigned integers in big endian format.

#### Address
Address format is defined by application and should have constant length.

#### Encryption
`{}` means data are encrypted (as the result of consuming `CREATE_REQUEST` and `CREATE_RESPONSE` and establishing corresponding encryption keys) and current node is capable of encrypting and/or decrypting it.
MAC is assumed to be present after encrypted data, but not shown explicitly.

#### Data structure notation
`[]` is used to specify a distinct piece of raw data (encrypted if placed under `{}`).
The size of the data piece is specified in bytes after colon like this: `[data: 2]`, if no size specified, then data occupies the rest of available space.
Exact value can be specified after data piece size separated by coma: `[data: 2, 1]`.

#### Packet format
```
[version: 1][circuit_ID: 2][request_data]
```

`[version]` encapsulates address format, crypto algorithms used, set of commands and other important details used on that connection, supplied by application.
Version is kept the same on each hop of the same routing path and never changes in the middle of the routing path.
`[circuit_ID]` is unique to each segment of the network, the response should always preserve `[circuit_ID]` of the request so that it is clear where to send it.

#### Packet size
Total packet size is fixed and configured by application, padding with random bytes is used when needed as described in corresponding sections.

It is responsibility of the application to carefully count how many bytes can be sent in each particular command type with selected encryption algorithm and make sure data will fit into one packet (or split data into multiple packets if needed).

#### [random_bytes_padding]
Is used at the end of the packet to fill it til packet size (so that all packets have the same size).

#### Commands
Commands explain what node should do with the packet it has received, supported commands are listed below.

Each command is represented by number from the range `1..255`.
The list of supported commands is given below, unused numbers are reserved for future versions of the specification:

| Command name    | Numeric value |
|-----------------|---------------|
| CREATE_REQUEST  | 1             |
| CREATE_RESPONSE | 2             |
| EXTEND_REQUEST  | 3             |
| EXTEND_RESPONSE | 4             |
| DATA            | 5             |

### Plain text commands
These commands are used prior to establishing circuit with specified `[circuit_ID]`, as soon as circuit is established only encrypted commands must be accepted

#### CREATE_REQUEST
Is sent when creating segment of routing path is needed, can be send multiple times to the same node if multiple roundtrips are needed.

Request data:
```
[command: 1, 1][circuit_creation_request_data_length: 2][circuit_creation_request_data: circuit_creation_request_data_length][random_bytes_padding]
```

Request data handling:
* only proceed if for `[circuit_ID]` circuit was not established yet, otherwise assume that contents is encrypted
* `[circuit_creation_request_data]` is consumed by the node in order to perform circuit creation
* `[circuit_ID]` is stored by application and associated with connection where the request came from
* responds to the previos node with `CREATE_RESPONSE` command

#### CREATE_RESPONSE
Is sent as an answer to `CREATE_REQUEST`, is sent exactly once in response to each `CREATE_REQUEST`.

Response data:
```
[command: 1, 2][circuit_creation_response_data_length: 2][circuit_creation_response_data: circuit_creation_response_data_length][random_bytes_padding]
```

Response data handling:
* if current node has initiated `CREATE_REQUEST` then `[circuit_creation_response_data]` is consumed by the node in order to perform circuit creation
* if current node has not initiated `CREATE_REQUEST`, but instead it `EXTEND_REQUEST` command was sent by another node, `EXTEND_RESPONSE` is generated in response

### Encrypted commands
These commands are used after establishing circuit with specified `[circuit_ID]`.

Each encrypted command request data follows following pattern:
```
{[command: 1][command_data_length: 2]}[command_data]
```

Where `[command_data_length]` bytes of `[command_data]` (not including MAC) also belong to the command, are encrypted separately and their meaning depends on the command.

#### EXTEND_REQUEST command
Is used in order to extend routing path one segment further, effectively generates `CREATE_REQUEST` to the next node.

Request data:
```
{[command: 1, 3][address_and_circuit_creation_request_data_length: 2]}{[next_node_address][circuit_creation_request_data]}[random_bytes_padding]
```

Request data handling:
* decrypt command and command data length
* if command is `EXTEND_REQUEST`, then decrypt `[next_node_address]` and `[circuit_creation_request_data]` then send `CREATE_REQUEST` command to the `[next_node_address]`

`CREATE_REQUEST` request data being sent:
```
[command: 1, 4][circuit_creation_request_data_length: 2][circuit_creation_request_data: circuit_creation_request_data_length][random_bytes_padding]
```

IMPORTANT: `[circuit_ID]` should be changed to `[circuit_ID]` that corresponds to the segment of routing path between current node and the next one.

#### EXTEND_RESPONSE command
Is used in order to extend routing path one segment further, effectively wraps `CREATE_RESPONSE` from next node.

Response data:
```
{[command][circuit_creation_response_data_length][circuit_creation_response_data]}[random_bytes_padding]
```

Where `[command][circuit_creation_response_data_length][circuit_creation_response_data]` part is taken from the beginning of the `CREATE_RESPONSE` data directly.

IMPORTANT: `[circuit_ID]` should be changed to `[circuit_ID]` that corresponds to the segment of routing path between current node and the previous one.

#### DATA command
Is used when data should be accepted by application layer.

`DATA` command doesn't differentiate request from response, it just send data, application layer should take care of delivery confirmations if necessary.

`DATA` command can be sent by:
* initiator towards any node in the routing path, including responder
* any node in the routing path, including responder, towards initiator

Request data:
```
{[command: 1, 5][data_length: 2]}{[data]}[random_bytes_padding]
```

#### Data forwarding
Only works after `EXTEND_REQUEST` and `EXTEND_RESPONSE` happened before, so that node knows where to send data next.

Forwarding is happening when node can't decrypt the command, which in turn means that the command was not intended for this node.
Also all of the data moving from responder to initiator are forwarded without command decryption attempt.

Data are forwarded to the next node unchanged except `[circuit_ID]`, that will be updated on each segment so that it is clear where to forward data next if there is a need to do so.

Initiator upon receiving the data tries to decrypt data with keys that correspond to each node in routing path until it decrypts data successfully.
The order in which keys are selected is up to the application or implementation, generally starting from the keys of the last node and moving to the first node in routing path is a good idea.

#### Undecryptable packets
If packets were forwarded through the whole path and the last node (either initiator or responder) still can't decrypt the packet, the packet is silently dropped.
