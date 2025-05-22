#pragma once

#include <vector>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include "message_types.hpp"

namespace pocol {

class Mempool {
public:
    Mempool();
    ~Mempool();

    // Add a transaction to the mempool
    bool add_transaction(const Transaction& tx);
    
    // Remove a transaction from the mempool
    bool remove_transaction(const std::string& txid);
    
    // Get all transactions sorted by fee rate
    std::vector<Transaction> get_sorted_transactions(const std::string& seed) const;
    
    // Get transaction by ID
    Transaction get_transaction(const std::string& txid) const;
    
    // Check if transaction exists
    bool has_transaction(const std::string& txid) const;
    
    // Get mempool size
    size_t size() const;
    
    // Clear mempool
    void clear();

private:
    // Deterministic sorting function based on seed
    static bool compare_transactions(const Transaction& a, const Transaction& b, const std::string& seed);
    
    // Calculate fee rate for a transaction
    static double calculate_fee_rate(const Transaction& tx);
    
    // XOR a txid with a seed for deterministic tie-breaking
    static std::string xor_with_seed(const std::string& txid, const std::string& seed);

    std::unordered_map<std::string, Transaction> transactions_;
    mutable std::shared_mutex mutex_;
};

} // namespace pocol
