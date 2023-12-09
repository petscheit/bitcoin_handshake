## Bitcoin P2P handshake challenge
This repo contains my submission for the P2P handshake coding challange. It is implemented in rust, using minimal dependencies, and handles peer connections in a non-blocking way. The implementation is configured to communicate with the Bitcoin mainnet, and contains all required configs.
### Handshake Protocol:
The implementation handles the P2P handshake between two nodes. The handshake consists of two nodes exchanging their version information with each other, and confirming this by responding with `verack`. The lifecycle of looks as follows:

```plaintext
Node A                                    Node B
  |                                         |
  |----- version message -----------------> | 
  |       [version, services, timestamp,    |
  |        addr_recv, addr_from, nonce,     |
  |        user_agent, start_height, relay] |
  |                                         |
  | <---- version message ------------------| 
  |       [version, services, timestamp,    |
  |        addr_recv, addr_from, nonce,     |
  |        user_agent, start_height, relay] |
  |                                         |
  |----- verack message ------------------->|
  |                                         |
  | <---- verack message -------------------|
  |                                         |
```
Once the `verack` messages are exchanged, the nodes are ready to communicate with each other and handle the protocol operations.

### Running:
`lib.rs` contains three hardcoded nodes, they can be seen as the bootnodes for the implementation. When running with `cargo run` the handshake will be performed for these nodes. A message will be printed in the terminal once the handshake has completed with a peer.

The handshake will not complete if we send an invalid message (e.g. incorrect checksum). In this case the peer will not respond. This can be simulated by hardcoding an incorrect value, e.g. the checksum.

### Implementation:
The peer (tcp stream) connections, which remain open after the handshake, are performed on a separate thread for each connected peer. Incoming messages are then sent back to the main thread via `mpsc` messages, allowing numerous peers to be connected in a non-blocking way. The main thread handles these messages, performing the required state-updates. The state can only be accessed by the main thread, ensuring no unexpected side effects arise.

### Testing:
The implementation currently only includes unit tests. While this covers some important aspects (e.g. rejecting invalid messages), it's quite incomplete. Below I am listing the untested parts, briefly outlining how I would approach testing them.

- **PeerTracker**: misses some basic CRUD tests (unit test)
- **networking.rs: Message handling**: ensure that the different message types are processed and decoded correctly (unit test)
- **Event Loop**: simulate the event loop, and test that messages are handled correctly (integration test)
- **Mock Network**: setup a mock network, consisting of other Bitcoin implementation. Ensure the network is running correctly and the node is performing all network tasks (e2e testing)



