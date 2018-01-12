# Ronion anonymous routing protocol framework design

Complements specification version: 0.8.0

Author: Nazar Mokrynskyi

License: Ronion anonymous routing protocol framework design (this document) is hereby placed in the public domain

### Introduction
This document is a high level design overview of the Ronion anonymous routing protocol framework.
The goal of this document is to give general understanding what Ronion is, how it works and why it is designed the way it is.

Refer to the specification if you intend to implement this framework.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in IETF [RFC 2119](http://www.ietf.org/rfc/rfc2119.txt).

### Glossary
* Initiator: the node that initiates communication
* Responder: the node with which initiator wants to communicate
* Routing path: a sequence of nodes that form a path through which initiator and responder are connected and can anonymously send encrypted data
* Routing path segment: part of routing path between 2 adjacent nodes, on each node routing path segment is identified using routing path segment identifier and address of the node on the other end of the segment
* Packet: set of bytes to be transferred from one node to another
* Recipient: the node in routing path to which initiator sent the packet (MIGHT be any node, not just responder)
* Application: software that uses implementation of this protocol

### What Ronion is and what isn't
Ronion's primary goal is to provide a well defined, easy to follow and secure protocol framework for anonymous routing that can be relied upon when building higher level protocols in order to reduce the number of decisions that need to be made.

The protocol framework is deliberately designed in a generic way, so that it would be possible to use it with different cryptographic algorithms, transport layers and nodes selection approaches.

This protocol framework (in contrast to Tor, mix net) doesn't specify how exactly nodes are selected and how many nodes SHOULD be in routing path - those are application layer decisions.
It only specifies how communication MUST happen and provides basic building blocks for higher level protocols.

This protocol framework also doesn't specify traffic shaping rules like applying custom delays, changing sending order of independent packets and other methods commonly found in mix networks.

In fact, this framework can be used as the foundation for Tor-like routing or mix network implementations.

### Assumptions
The only assumption about encryption algorithm used is that authenticated encryption is used (application MUST specify MAC length in bytes).

However, since encryption algorithm in use is crucial for the whole protocol security and anonymity properties, encryption algorithm SHOULD also provide:
* perfect forward secrecy
* encryption SHOULD produce different ciphertext during encryption each time even if plaintext being encrypted is the same
* decryption SHOULD be resistant to replay attacks (if packet was decrypted by decryption object once, it MUST NOT successfully decrypt the same packet again because of changed internal state)
* initiator SHOULD use random, unique one-time keys for any routing path it tries it creates and for each routing path segment

Protocol relies heavily on the right choice of encryption by application and will not be secure if choices being made are not secure.

The only assumption about transport layer is that it delivers data in the same order as the data were sent (think of TCP instead of UDP, no out-of-order delivery).

Following events will cause routing path to be unable to successfully send any packets past the segment in routing path where event took place:
* dropped packet (this also includes sending packets out-of-order)
* modified packet

Protocol doesn't include any indication of broken routing path, so timeouts, ping/pong packets or other approaches could be used to ensure working connection.

### Design goals
The goal of this protocol framework design is to define end-to-end encrypted communication channel between initiator and responder through the routing path that has the following properties:
1. Any node in routing path that is not recipient of the packet MUST know nothing about packet contents
2. Any node in routing path that is not recipient of the packet MUST NOT know packet origin and/or destination besides the fact that packet come from previous node and SHOULD be sent to the next node
3. Recipient node MUST be able decrypt packet contents, but MUST NOT be able to initiator's address and which nodes build up routing path besides the node it received encrypted packet from
4. Any recipient MUST be able to send data back to the initiator
5. Limited observer (doesn't control all of the nodes of routing path part from initiator to recipient) MUST NOT be able to prove that initiator speaks to recipient (and vice versa) purely from packets contents (timing and correlation attacks are not mitigated by this protocol, but MIGHT be mitigated to some extent on application level)

### Packet contents hiding
All packets have fixed size.

If data doesn't fit into single packet - application SHOULD take care of splitting data into multiple packets.
If data doesn't fill the whole packet - padding is used.

As the result, any packet looks to external observer just like any other packet - exactly the same size, exactly the same random data.

Each packet (besides initial packets that are needed to establish encryption keys) are encrypted (described below).
If packet was not targeted at current node, it has no idea to even know whether packet contains valid data or just garbage.

This aspect covers design goal #1.

### Packets route hiding
Each encrypted packet (end-to-end authenticated encryption) is additionally encrypted multiple times on top (without authentication).

Let's say node A wants to send data to node E through nodes B, C and D.

In this case node A MUST first apply authenticated encryption for node E, then apply non-authenticated encryption for nodes E, D, C and B.

Resulting packet will be sent to the node B, which will apply non-authenticated decryption unconditionally and then will try to apply authenticated decryption.
If authenticated decryption fails, it will send packet further. Node C and D will do the same and only on node E authenticated decryption will succeed, which means node E was intended recipient.

This is very similar to Tor's onion.

When node D wants to send data to initiator A, it will apply authenticated encryption first and non-authenticated encryption on top of it, then will send data to the node C.
Non-authenticated encryption for packets sent towards initiator MUST use different keys than for packets that are sent from initiator.
Because of reverse direction, node C will just apply non-authenticated encryption and send data to the node B. Node B will do the same as C and will send data to the node A.
Node A will first apply non-authenticated decryption for node B and will try do make authenticated decryption as if packet originated from node B.
If authenticated decryption fails, node A will try the same for nodes C, D and only for node E it will successfully decrypt the packet, which means that packet originated from node E.

This way node A always knows who have sent the packet and knows where packet is going.
However, nodes in the middle just apply non-authenticated decryption + authenticated decryption on the way from initiator and non-authenticated encryption without decryption attempt on the way towards initiator.

Authenticated encryption hides address of the initiator from everyone besides initiator and hides address of the recipient from anyone besides initiator and recipient.
This aspect covers design goals #2, #3 and  #4.

Non-authenticated encryption causes packet contents to be different on segments A-B, B-C, C-D and D-E, so that limited observer is not able to follow encrypted packet forwarding across different segments of the routing path. Also number of non-authenticated encryptions/decryptions doesn't affect packet size.
This aspect covers design goal #5.

### Packets forwarding diagrams
`[Xi:packet]` means authenticated encryption of the packet for node `X` by initiator.
`[Xf[X:packet]]` means non-authenticated encryption for node `X` by initiator was applied on top of `[Xi:packet]`.
`[Xr:packet]` means authenticated encryption of the packet for initiator by node `X`.
`[Xb[Xi:packet]]` means non-authenticated encryption for initiator by node `X` was applied on top of `[Xr:packet]`.

Sending data from node A to node E and from node D to node A:
```
| A                              | B                              | C                              | D                              | E                              |
| [Bf[Cf[Df[Ef[Ei:packet]]]]]    |                                |                                |                                |                                |
| > Encrypted everything         |                                |                                |                                |                                |
|                                | [Cf[Df[Ef[Ei:packet]]]]        |                                |                                |                                |
|                                | > Decrypted [Bf]               |                                |                                |                                |
|                                |                                | [Df[Ef[Ei:packet]]]            |                                |                                |
|                                |                                | > Decrypted [Cf]               |                                |                                |
|                                |                                |                                | [Ef[Ei:packet]]                |                                |
|                                |                                |                                | > Decrypted [Df]               |                                |
|                                |                                |                                |                                | packet                         |
|                                |                                |                                |                                | ^ Decrypted [Ef] and [Ei]      |
|                                |                                |                                | [Db[Dr:packet]]                |                                |
|                                |                                |                                | < Encrypted with [Dr] and [Db] |                                |
|                                |                                | [Cb[Db[Dr:packet]]]            |                                |                                |
|                                |                                | < Encrypted with [Cb]          |                                |                                |
|                                | [Bb[Cb[Db[Dr:packet]]]]        |                                |                                |                                |
|                                | < Encrypted with [Bb]          |                                |                                |                                |
| packet                         |                                |                                |                                |                                |
| ^ Decrypted everything         |                                |                                |                                |                                |
```

### Routing path creation diagram
Routing path creation starts with `CREATE_REQUEST`/`CREATE_RESPONSE` commands sent to the first node in routing path.
Then initiator sends `EXTEND_REQUEST`/`EXTEND_RESPONSE` (this time encrypted) commands to the last node in routing path, extending routing path one segment at a time until the last node in routing path is responder.

Creating routing path from A through B to C:
```
| A                                    | B                                    | C                                    |
| CREATE_REQUEST                       |                                      |                                      |
| > Start first segment                |                                      |                                      |
|                                      | CREATE_RESPONSE                      |                                      |
|                                      | < Respond to segment creation        |                                      |
| ^ First segment established          |                                      |                                      |
| [Bf[Bi:EXTEND_REQUEST]]              |                                      |                                      |
| > Extending by one more segment      |                                      |                                      |
|                                      | CREATE_REQUEST                       |                                      |
|                                      | > Start new segment                  |                                      |
|                                      |                                      | CREATE_RESPONSE                      |
|                                      |                                      | < Respond to segment creation        |
|                                      | [Bb[Br:EXTEND_RESPONSE]]             |                                      |
|                                      | < Wrapping segment creation response |                                      |
| ^ Routing path established           |                                      |                                      |
```

### Acknowledgements
This protocol framework is heavily inspired by [Tor](https://www.torproject.org/).

The crypto layer that was kept in mind throughout designing was `NK` handshake pattern from [The Noise Protocol Framework](https://noiseprotocol.org/).

Many thanks to Andriy Khavryuсhenko, Ximin Luo and Jeff Burdges for review and/or valuable suggestions!
