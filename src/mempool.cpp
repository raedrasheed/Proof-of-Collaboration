#include "../include/mempool.hpp"
#include "../include/transaction_utils.hpp"
#include "../include/utxo_set.hpp"
#include <algorithm>
#include <functional>
#include <openssl/sha.h>

namespace pocol {

Mempool::Mempool() {
}

Mempool::~Mempool() {
}

bool Mempool::add_transaction(const Transaction& tx) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    // Check if transaction already exists
    std::string txid = tx.txid;
    if (transactions_.find(txid) != transactions_.end()) {
        return false;
    }
    
    // Validate the transaction using the UTXO set
    if (!validate_transaction(tx)) {
        return false;
    }
    
    // Add the transaction
    transactions_[txid] = tx;
    return true;
}

bool Mempool::remove_transaction(const std::string& txid) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    // Check if transaction exists
    auto it = transactions_.find(txid);
    if (it == transactions_.end()) {
        return false;
    }
    
    // Remove the transaction
    transactions_.erase(it);
    return true;
}

std::vector<Transaction> Mempool::get_sorted_transactions(const std::string& seed) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    // Copy transactions to a vector
    std::vector<Transaction> result;
    result.reserve(transactions_.size());
    
    for (const auto& pair : transactions_) {
        result.push_back(pair.second);
    }
    
    // Sort transactions by fee rate and seed-based tie-breaker
    std::sort(result.begin(), result.end(), 
              [this, &seed](const Transaction& a, const Transaction& b) {
                  return compare_transactions(a, b, seed);
              });
    
    return result;
}

Transaction Mempool::get_transaction(const std::string& txid) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    auto it = transactions_.find(txid);
    if (it != transactions_.end()) {
        return it->second;
    }
    
    return Transaction();
}

bool Mempool::has_transaction(const std::string& txid) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return transactions_.find(txid) != transactions_.end();
}

size_t Mempool::size() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return transactions_.size();
}

void Mempool::clear() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    transactions_.clear();
}

bool Mempool::compare_transactions(const Transaction& a, const Transaction& b, const std::string& seed) {
    // First, compare by fee rate (higher fee rate first)
    double fee_rate_a = calculate_fee_rate(a);
    double fee_rate_b = calculate_fee_rate(b);
    
    if (fee_rate_a != fee_rate_b) {
        return fee_rate_a > fee_rate_b;
    }
    
    // If fee rates are equal, use seed-based tie-breaker
    std::string txid_a = a.txid;
    std::string txid_b = b.txid;
    
    std::string xor_a = xor_with_seed(txid_a, seed);
    std::string xor_b = xor_with_seed(txid_b, seed);
    
    return xor_a < xor_b;
}

double Mempool::calculate_fee_rate(const Transaction& tx) {
    // Calculate the fee rate (fee / size)
    // For simplicity, we'll use the fee directly
    return static_cast<double>(tx.fee);
}

std::string Mempool::xor_with_seed(const std::string& txid, const std::string& seed) {
    // XOR the txid with the seed for deterministic tie-breaking
    std::string result = txid;
    
    for (size_t i = 0; i < result.size() && i < seed.size(); ++i) {
        result[i] = result[i] ^ seed[i];
    }
    
    return result;
}

} // namespace pocol
