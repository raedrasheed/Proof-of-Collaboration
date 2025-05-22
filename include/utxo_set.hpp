#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <vector>
#include "message_types.hpp"

namespace pocol {

// Structure to represent a transaction output
struct TransactionOutput {
    std::string txid;       // Transaction ID this output belongs to
    uint32_t index;         // Output index in the transaction
    std::string address;    // Address (public key) that owns this output
    int64_t amount;         // Amount of coins
    bool is_spent;          // Whether this output has been spent
};

// Structure to represent a transaction input reference
struct OutPoint {
    std::string txid;       // Transaction ID being referenced
    uint32_t index;         // Output index being referenced

    // Equality operator for use in maps
    bool operator==(const OutPoint& other) const {
        return txid == other.txid && index == other.index;
    }
};

// Hash function for OutPoint to use in unordered_map
struct OutPointHash {
    std::size_t operator()(const OutPoint& outpoint) const {
        return std::hash<std::string>()(outpoint.txid) ^ std::hash<uint32_t>()(outpoint.index);
    }
};

class UTXOSet {
public:
    UTXOSet();
    ~UTXOSet();

    // Add a new transaction's outputs to the UTXO set
    bool add_transaction(const Transaction& tx);
    
    // Remove spent outputs when a transaction is processed
    bool spend_outputs(const Transaction& tx);
    
    // Check if a transaction is valid (all inputs reference valid UTXOs)
    bool validate_transaction(const Transaction& tx) const;
    
    // Get the balance for an address
    int64_t get_balance(const std::string& address) const;
    
    // Get all UTXOs for an address
    std::vector<TransactionOutput> get_utxos_for_address(const std::string& address) const;
    
    // Get a specific UTXO
    TransactionOutput get_utxo(const std::string& txid, uint32_t index) const;
    
    // Check if a UTXO exists
    bool has_utxo(const std::string& txid, uint32_t index) const;
    
    // Get the total number of UTXOs
    size_t size() const;
    
    // Clear all UTXOs (for testing)
    void clear();

private:
    // Map from outpoint (txid + index) to transaction output
    std::unordered_map<OutPoint, TransactionOutput, OutPointHash> utxos_;
    
    // Map from address to a list of outpoints owned by that address
    std::unordered_map<std::string, std::vector<OutPoint>> address_to_utxos_;
    
    // Mutex for thread safety
    mutable std::mutex mutex_;
};

} // namespace pocol
