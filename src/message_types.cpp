#include "../include/message_types.hpp"
#include <sstream>
#include <iomanip>

namespace pocol {

// Simple serialization format: field1|field2|field3|...
// For complex types like vectors and maps, we use additional delimiters

// Helper functions
std::string serialize_string(const std::string& str) {
    std::stringstream ss;
    for (char c : str) {
        if (c == '|' || c == ',' || c == ':') {
            ss << '\\' << c;
        } else if (c == '\\') {
            ss << "\\\\";
        } else {
            ss << c;
        }
    }
    return ss.str();
}

std::string deserialize_string(const std::string& str) {
    std::stringstream ss;
    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '\\' && i + 1 < str.size()) {
            ss << str[++i];
        } else {
            ss << str[i];
        }
    }
    return ss.str();
}

std::string serialize_version(const Version& version) {
    std::stringstream ss;
    ss << version.version << '|'
       << serialize_string(version.user_agent) << '|'
       << version.timestamp << '|'
       << version.nonce;
    return ss.str();
}

bool deserialize_version(const std::string& data, Version& version) {
    std::stringstream ss(data);
    std::string token;
    
    if (!std::getline(ss, token, '|')) return false;
    version.version = std::stoi(token);
    
    if (!std::getline(ss, token, '|')) return false;
    version.user_agent = deserialize_string(token);
    
    if (!std::getline(ss, token, '|')) return false;
    version.timestamp = std::stoll(token);
    
    if (!std::getline(ss, token)) return false;
    version.nonce = std::stoi(token);
    
    return true;
}

std::string serialize_verack(const VerAck& verack) {
    return verack.acknowledged ? "1" : "0";
}

bool deserialize_verack(const std::string& data, VerAck& verack) {
    verack.acknowledged = (data == "1");
    return true;
}

std::string serialize_transaction(const Transaction& transaction) {
    std::stringstream ss;
    ss << serialize_string(transaction.txid) << '|';
    
    // Serialize inputs
    for (size_t i = 0; i < transaction.inputs.size(); ++i) {
        if (i > 0) ss << ',';
        ss << serialize_string(transaction.inputs[i]);
    }
    ss << '|';
    
    // Serialize outputs
    for (size_t i = 0; i < transaction.outputs.size(); ++i) {
        if (i > 0) ss << ',';
        ss << serialize_string(transaction.outputs[i]);
    }
    ss << '|'
       << transaction.fee << '|'
       << transaction.timestamp;
    
    return ss.str();
}

bool deserialize_transaction(const std::string& data, Transaction& transaction) {
    std::stringstream ss(data);
    std::string token;
    
    if (!std::getline(ss, token, '|')) return false;
    transaction.txid = deserialize_string(token);
    
    // Deserialize inputs
    if (!std::getline(ss, token, '|')) return false;
    std::stringstream inputs_ss(token);
    std::string input;
    transaction.inputs.clear();
    while (std::getline(inputs_ss, input, ',')) {
        if (!input.empty()) {
            transaction.inputs.push_back(deserialize_string(input));
        }
    }
    
    // Deserialize outputs
    if (!std::getline(ss, token, '|')) return false;
    std::stringstream outputs_ss(token);
    std::string output;
    transaction.outputs.clear();
    while (std::getline(outputs_ss, output, ',')) {
        if (!output.empty()) {
            transaction.outputs.push_back(deserialize_string(output));
        }
    }
    
    if (!std::getline(ss, token, '|')) return false;
    transaction.fee = std::stoll(token);
    
    if (!std::getline(ss, token)) return false;
    transaction.timestamp = std::stoll(token);
    
    return true;
}

std::string serialize_block(const Block& block) {
    std::stringstream ss;
    ss << serialize_string(block.hash) << '|'
       << serialize_string(block.prev_hash) << '|'
       << block.timestamp << '|'
       << block.nonce << '|'
       << serialize_string(block.merkle_root) << '|'
       << serialize_string(block.share_merkle_root) << '|';
    
    // Serialize transactions
    for (size_t i = 0; i < block.transactions.size(); ++i) {
        if (i > 0) ss << ',';
        ss << serialize_string(serialize_transaction(block.transactions[i]));
    }
    ss << '|';
    
    // Serialize share table
    bool first = true;
    for (const auto& pair : block.share_table) {
        if (!first) ss << ',';
        first = false;
        ss << serialize_string(pair.first) << ':' << pair.second;
    }
    
    return ss.str();
}

bool deserialize_block(const std::string& data, Block& block) {
    std::stringstream ss(data);
    std::string token;
    
    if (!std::getline(ss, token, '|')) return false;
    block.hash = deserialize_string(token);
    
    if (!std::getline(ss, token, '|')) return false;
    block.prev_hash = deserialize_string(token);
    
    if (!std::getline(ss, token, '|')) return false;
    block.timestamp = std::stoll(token);
    
    if (!std::getline(ss, token, '|')) return false;
    block.nonce = std::stoi(token);
    
    if (!std::getline(ss, token, '|')) return false;
    block.merkle_root = deserialize_string(token);
    
    if (!std::getline(ss, token, '|')) return false;
    block.share_merkle_root = deserialize_string(token);
    
    // Deserialize transactions
    if (!std::getline(ss, token, '|')) return false;
    std::stringstream txs_ss(token);
    std::string tx_str;
    block.transactions.clear();
    while (std::getline(txs_ss, tx_str, ',')) {
        if (!tx_str.empty()) {
            Transaction tx;
            if (deserialize_transaction(deserialize_string(tx_str), tx)) {
                block.transactions.push_back(tx);
            }
        }
    }
    
    // Deserialize share table
    if (!std::getline(ss, token)) return false;
    std::stringstream share_table_ss(token);
    std::string pair_str;
    block.share_table.clear();
    while (std::getline(share_table_ss, pair_str, ',')) {
        if (!pair_str.empty()) {
            std::stringstream pair_ss(pair_str);
            std::string key, value;
            if (std::getline(pair_ss, key, ':') && std::getline(pair_ss, value)) {
                block.share_table[deserialize_string(key)] = std::stoi(value);
            }
        }
    }
    
    return true;
}

std::string serialize_range_request(const RangeRequest& range_request) {
    std::stringstream ss;
    ss << range_request.range_id << '|'
       << serialize_string(range_request.miner_id);
    return ss.str();
}

bool deserialize_range_request(const std::string& data, RangeRequest& range_request) {
    std::stringstream ss(data);
    std::string token;
    
    if (!std::getline(ss, token, '|')) return false;
    range_request.range_id = std::stoi(token);
    
    if (!std::getline(ss, token)) return false;
    range_request.miner_id = deserialize_string(token);
    
    return true;
}

std::string serialize_range_complete(const RangeComplete& range_complete) {
    std::stringstream ss;
    ss << range_complete.range_id << '|'
       << serialize_string(range_complete.miner_id);
    return ss.str();
}

bool deserialize_range_complete(const std::string& data, RangeComplete& range_complete) {
    std::stringstream ss(data);
    std::string token;
    
    if (!std::getline(ss, token, '|')) return false;
    range_complete.range_id = std::stoi(token);
    
    if (!std::getline(ss, token)) return false;
    range_complete.miner_id = deserialize_string(token);
    
    return true;
}

std::string serialize_share(const Share& share) {
    std::stringstream ss;
    ss << serialize_string(share.header) << '|'
       << share.nonce << '|'
       << serialize_string(share.proof) << '|'
       << serialize_string(share.miner_id);
    return ss.str();
}

bool deserialize_share(const std::string& data, Share& share) {
    std::stringstream ss(data);
    std::string token;
    
    if (!std::getline(ss, token, '|')) return false;
    share.header = deserialize_string(token);
    
    if (!std::getline(ss, token, '|')) return false;
    share.nonce = std::stoi(token);
    
    if (!std::getline(ss, token, '|')) return false;
    share.proof = deserialize_string(token);
    
    if (!std::getline(ss, token)) return false;
    share.miner_id = deserialize_string(token);
    
    return true;
}

std::string serialize_network_message(const NetworkMessage& message) {
    std::stringstream ss;
    ss << static_cast<int>(message.type) << '|';
    
    switch (message.type) {
        case MessageType::VERSION:
            ss << serialize_version(message.version);
            break;
        case MessageType::VERACK:
            ss << serialize_verack(message.verack);
            break;
        case MessageType::TRANSACTION:
            ss << serialize_transaction(message.transaction);
            break;
        case MessageType::BLOCK:
            ss << serialize_block(message.block);
            break;
        case MessageType::RANGE_REQUEST:
            ss << serialize_range_request(message.range_request);
            break;
        case MessageType::RANGE_COMPLETE:
            ss << serialize_range_complete(message.range_complete);
            break;
        case MessageType::SHARE:
            ss << serialize_share(message.share);
            break;
    }
    
    return ss.str();
}

bool deserialize_network_message(const std::string& data, NetworkMessage& message) {
    std::stringstream ss(data);
    std::string token;
    
    if (!std::getline(ss, token, '|')) return false;
    message.type = static_cast<MessageType>(std::stoi(token));
    
    if (!std::getline(ss, token)) return false;
    
    switch (message.type) {
        case MessageType::VERSION:
            return deserialize_version(token, message.version);
        case MessageType::VERACK:
            return deserialize_verack(token, message.verack);
        case MessageType::TRANSACTION:
            return deserialize_transaction(token, message.transaction);
        case MessageType::BLOCK:
            return deserialize_block(token, message.block);
        case MessageType::RANGE_REQUEST:
            return deserialize_range_request(token, message.range_request);
        case MessageType::RANGE_COMPLETE:
            return deserialize_range_complete(token, message.range_complete);
        case MessageType::SHARE:
            return deserialize_share(token, message.share);
        default:
            return false;
    }
}

} // namespace pocol
