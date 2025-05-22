#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <ctime>

namespace pocol {

// Simple message types that don't depend on Protocol Buffers

// Network messages
struct Version {
    int32_t version;
    std::string user_agent;
    int64_t timestamp;
    int32_t nonce;
};

struct VerAck {
    bool acknowledged;
};

struct Transaction {
    std::string txid;
    std::vector<std::string> inputs;
    std::vector<std::string> outputs;
    int64_t fee;
    int64_t timestamp;
};

struct Block {
    std::string hash;
    std::string prev_hash;
    int64_t timestamp;
    int32_t nonce;
    std::string merkle_root;
    std::string share_merkle_root; // Merkle root of all valid shares
    std::vector<Transaction> transactions;
    std::unordered_map<std::string, int32_t> share_table; // Miner ID -> share count
};

struct RangeRequest {
    int32_t range_id;
    std::string miner_id;
};

struct RangeComplete {
    int32_t range_id;
    std::string miner_id;
};

struct Share {
    std::string header;
    int32_t nonce;
    std::string proof;
    std::string miner_id;
};

enum class MessageType {
    VERSION,
    VERACK,
    TRANSACTION,
    BLOCK,
    RANGE_REQUEST,
    RANGE_COMPLETE,
    SHARE
};

struct NetworkMessage {
    MessageType type;
    
    // Union-like structure for the payload
    Version version;
    VerAck verack;
    Transaction transaction;
    Block block;
    RangeRequest range_request;
    RangeComplete range_complete;
    Share share;
};

// Serialization functions
std::string serialize_version(const Version& version);
bool deserialize_version(const std::string& data, Version& version);

std::string serialize_verack(const VerAck& verack);
bool deserialize_verack(const std::string& data, VerAck& verack);

std::string serialize_transaction(const Transaction& transaction);
bool deserialize_transaction(const std::string& data, Transaction& transaction);

std::string serialize_block(const Block& block);
bool deserialize_block(const std::string& data, Block& block);

std::string serialize_range_request(const RangeRequest& range_request);
bool deserialize_range_request(const std::string& data, RangeRequest& range_request);

std::string serialize_range_complete(const RangeComplete& range_complete);
bool deserialize_range_complete(const std::string& data, RangeComplete& range_complete);

std::string serialize_share(const Share& share);
bool deserialize_share(const std::string& data, Share& share);

std::string serialize_network_message(const NetworkMessage& message);
bool deserialize_network_message(const std::string& data, NetworkMessage& message);

} // namespace pocol
