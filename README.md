# Proof-of-Collaboration (PoCol) Blockchain

A novel blockchain implementation using the Proof-of-Collaboration consensus algorithm, which replaces the energy-wasteful, winner-takes-all mining of Proof-of-Work with a fully cooperative, deterministic, and fair process.

## Features

- **Collaborative Mining**: All miners work together on the same block template—there is no secret, competitive race.
- **Distributed Nonce Search**: The 2³²-nonce space is deterministically partitioned each round so no two miners ever duplicate work.
- **Deterministic Block-Template Construction**: Every node independently builds an identical candidate block by sorting the fully-gossiped mempool with a shared, seed-based tie-breaker.
- **Full Gossip Mempool**: Transactions are gossiped and stored uniformly by all nodes.
- **Equitable Reward Distribution**: The block reward is split proportionally among everyone who contributed valid "shares" for that block template.
- **Lightweight, No-Validator Model**: There are no special "validator" nodes or signatures beyond miners' share submissions.

## Building from Source

### Prerequisites

- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- CMake 3.14+
- Boost 1.66+
- OpenSSL 1.1.1+
- Protobuf 3.0+
- GoogleTest 1.8+

### Build Instructions

\`\`\`bash
# Clone the repository
git clone https://github.com/yourusername/pocol.git
cd pocol

# Create build directory
mkdir build && cd build

# Configure and build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# Run tests
ctest

# Install binaries
sudo make install
\`\`\`

## Running the Node

\`\`\`bash
# Start the PoCol daemon
pocold --p2p-port 8333 --rpc-port 8332 --miner-id your-miner-id

# Use the CLI to interact with the daemon
pocol-cli --host localhost --port 8332
\`\`\`

## RPC Interface

The PoCol daemon exposes a JSON-RPC interface over HTTP on the specified RPC port. The following methods are available:

### `getpocoltemplate`

Returns the current deterministic block template.

**Parameters**: None

**Example**:
\`\`\`json
{
  "jsonrpc": "2.0",
  "method": "getpocoltemplate",
  "params": "",
  "id": 1
}
\`\`\`

### `requestpocolrange`

Claims the next available nonce range for mining.

**Parameters**: None

**Example**:
\`\`\`json
{
  "jsonrpc": "2.0",
  "method": "requestpocolrange",
  "params": "",
  "id": 1
}
\`\`\`

### `submitpocolshare`

Submits a share proof.

**Parameters**:
- `header`: Block header (hex string)
- `nonce`: Nonce value (integer)

**Example**:
\`\`\`json
{
  "jsonrpc": "2.0",
  "method": "submitpocolshare",
  "params": {
    "header": "0000000000000000000000000000000000000000000000000000000000000000",
    "nonce": 12345
  },
  "id": 1
}
\`\`\`

### `getpocolbalance`

Queries the accumulated share balance for a miner.

**Parameters**:
- `miner_id`: Miner identifier (string)

**Example**:
\`\`\`json
{
  "jsonrpc": "2.0",
  "method": "getpocolbalance",
  "params": {
    "miner_id": "miner1"
  },
  "id": 1
}
\`\`\`

## PoCol Protocol Description

### Networking & Gossip

The PoCol blockchain uses a TCP peer-to-peer overlay network with a standard gossip protocol for propagating transactions, range requests/completions, shares, and new blocks. Nodes perform a handshake via VERSION messages when connecting to peers.

### Mempool Management

All nodes maintain identical mempools, with transactions prioritized by fee-rate. When a node receives a new transaction, it validates it and adds it to the mempool, then gossips it to all peers.

### Block Template Construction

Block templates are constructed deterministically using the previous block's hash as a seed:

1. Sort the mempool by (fee_rate DESC, txid XOR seed ASC)
2. Pack up to 1 MiB of transactions into the template
3. Create a merkle root from the selected transactions
4. Create a block header with the merkle root, previous block hash, and timestamp

Since every node runs the same code with the same inputs, they all produce identical templates.

### Distributed Nonce Search Protocol

The 32-bit nonce space is split into equal ranges (configurable size). When a new block template is created:

1. Each miner calculates the same ordered list of ranges by seeded shuffling of [0...0xFFFFFFFF]
2. A miner broadcasts RANGE_REQUEST(range_id), others acknowledge, then it works exclusively on that range
3. On finishing without finding a block, the miner broadcasts RANGE_COMPLETE(range_id)
4. The next miner in line picks up the next range

This ensures no two miners ever cover the same nonces, eliminating redundant work.

### Mining Loop & Share Submission

For each assigned nonce in a range, the miner:

1. Computes H = SHA256(SHA256(header || nonce))
2. If H < block_target: broadcasts the full block
3. Else if H < share_target: broadcasts SHARE(header, nonce, proof)
4. On new template or tip, aborts and rebuilds

### Equitable Reward Distribution

A PoCol block includes in its coinbase:

1. A Merkle root of all valid share preimages
2. A share table mapping miner IDs to share counts

Upon block acceptance, each node automatically pays out block_reward × (miner_shares / total_shares) to each miner who contributed shares.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
\`\`\`

Let's also implement a simple test file to demonstrate how the testing would work:

```cpp file="test/network_test.cpp"
#include <gtest/gtest.h>
#include "network.hpp"

namespace pocol {
namespace test {

class NetworkTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup code
    }

    void TearDown() override {
        // Teardown code
    }
};

TEST_F(NetworkTest, PeerConnectionTest) {
    // Create a network instance
    Network network(8334);
    
    // Start the network
    network.start();
    
    // Connect to a peer (this is a mock test, so we're not actually connecting)
    bool connected = network.connect_to_peer("127.0.0.1", 8335);
    
    // In a real test, we'd check if the connection was successful
    // For now, we'll just assert that the function returns false since there's no peer
    ASSERT_FALSE(connected);
    
    // Stop the network
    network.stop();
}

TEST_F(NetworkTest, MessageBroadcastTest) {
    // Create a network instance
    Network network(8334);
    
    // Start the network
    network.start();
    
    // Create a message
    NetworkMessage message;
    message.set_type(NetworkMessage::VERSION);
    
    Version* version = message.mutable_version();
    version->set_version(1);
    version->set_user_agent("test");
    version->set_timestamp(time(nullptr));
    version->set_nonce(12345);
    
    // Broadcast the message (should return false since there are no peers)
    bool broadcast = network.broadcast_message(message);
    ASSERT_FALSE(broadcast);
    
    // Stop the network
    network.stop();
}

} // namespace test
} // namespace pocol
