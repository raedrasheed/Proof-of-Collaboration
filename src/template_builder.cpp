#include "../include/template_builder.hpp"
#include "../include/crypto_utils.hpp"
#include "../include/transaction_utils.hpp"
#include "../include/utxo_set.hpp"
#include "../include/string_utils.hpp"  // Add this line
#include <openssl/sha.h>
#include <algorithm>
#include <chrono>
#include <iostream>

namespace pocol {

TemplateBuilder::TemplateBuilder(std::shared_ptr<Mempool> mempool)
    : mempool_(mempool) {
}

TemplateBuilder::~TemplateBuilder() {
}

Block TemplateBuilder::build_template(const std::string& prev_block_hash) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    // Create a new block template
    Block block;
    
    // Set the previous block hash
    block.prev_hash = prev_block_hash;
    
    // Set the timestamp
    block.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    
    // Get sorted transactions from the mempool
    std::vector<Transaction> sorted_txs = mempool_->get_sorted_transactions(prev_block_hash);
    
    // Add transactions to the block (up to MAX_BLOCK_SIZE)
    size_t current_size = 0;
    for (const auto& tx : sorted_txs) {
        // Calculate the size of the transaction
        // For simplicity, we'll estimate the size based on the txid and input/output counts
        size_t tx_size = tx.txid.size() + tx.inputs.size() * 32 + tx.outputs.size() * 32;
        
        // Check if adding this transaction would exceed the block size limit
        if (current_size + tx_size > MAX_BLOCK_SIZE) {
            break;
        }
        
        // Add the transaction to the block
        block.transactions.push_back(tx);
        current_size += tx_size;
    }
    
    // Create the merkle root
    std::string merkle_root = create_merkle_root(block.transactions);
    block.merkle_root = merkle_root;
    
    // Initialize the share merkle root and share table
    block.share_merkle_root = "";
    
    // Store the current template
    current_template_ = block;
    
    // Clear the shares for the new template
    shares_.clear();
    
    return block;
}

void TemplateBuilder::update_template(const std::string& prev_block_hash) {
    build_template(prev_block_hash);
}

bool TemplateBuilder::add_share(const Share& share) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    // Validate the share
    if (!validate_share(share)) {
        return false;
    }
    
    // Add the share
    shares_.push_back(share);
    
    // Update the share merkle root
    std::string share_merkle_root = create_share_merkle_root(shares_);
    current_template_.share_merkle_root = share_merkle_root;
    
    return true;
}

Block TemplateBuilder::finalize_block(int32_t nonce) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    // Set the nonce
    current_template_.nonce = nonce;
    
    // Calculate the block hash
    std::string header = current_template_.prev_hash + 
                         current_template_.merkle_root + 
                         std::to_string(current_template_.timestamp) + 
                         std::to_string(nonce);
    
    // Use the compute_double_sha256 function from crypto_utils.hpp
    std::string binary_hash = compute_double_sha256(header);
    
    // Convert to hex string for readability
    std::string hash = bytes_to_hex_string(binary_hash);
    
    // Set the block hash
    current_template_.hash = hash;
    
    // Create a copy of the finalized block
    Block finalized_block = current_template_;
    
    // Update the UTXO set with the transactions in the block
    UTXOSet& utxo_set = get_utxo_set();
    
    // First, spend the inputs of all transactions
    for (const auto& tx : finalized_block.transactions) {
        utxo_set.spend_outputs(tx);
    }
    
    // Then, add the outputs of all transactions
    for (const auto& tx : finalized_block.transactions) {
        utxo_set.add_transaction(tx);
    }
    
    // Remove the transactions from the mempool
    for (const auto& tx : finalized_block.transactions) {
        mempool_->remove_transaction(tx.txid);
    }
    
    // Build a new template for the next block (use hex hash)
    build_template(hash);
    
    return finalized_block;
}

std::string TemplateBuilder::create_merkle_root(const std::vector<Transaction>& transactions) const {
    if (transactions.empty()) {
        // Return a default merkle root for empty blocks (hex zeros)
        return std::string(64, '0'); // 32 bytes = 64 hex characters
    }
    
    // Create a vector of transaction hashes
    std::vector<std::string> hashes;
    for (const auto& tx : transactions) {
        hashes.push_back(tx.txid);
    }
    
    // Build the merkle tree
    while (hashes.size() > 1) {
        std::vector<std::string> new_hashes;
        
        for (size_t i = 0; i < hashes.size(); i += 2) {
            std::string combined;
            
            if (i + 1 < hashes.size()) {
                combined = hashes[i] + hashes[i + 1];
            } else {
                combined = hashes[i] + hashes[i]; // Duplicate the last hash if there's an odd number
            }
            
            // Use the compute_double_sha256 function and convert to hex
            std::string binary_hash = compute_double_sha256(combined);
            new_hashes.push_back(bytes_to_hex_string(binary_hash));
        }
        
        hashes = new_hashes;
    }
    
    return hashes[0];
}

std::string TemplateBuilder::create_share_merkle_root(const std::vector<Share>& shares) const {
    if (shares.empty()) {
        // Return a default merkle root for empty shares (hex zeros)
        return std::string(64, '0'); // 32 bytes = 64 hex characters
    }
    
    // Create a vector of share hashes
    std::vector<std::string> hashes;
    for (const auto& share : shares) {
        // Hash the share
        std::string share_data = share.header + std::to_string(share.nonce) + share.proof;
        
        // Use the compute_sha256 function and convert to hex
        std::string binary_hash = compute_sha256(share_data);
        hashes.push_back(bytes_to_hex_string(binary_hash));
    }
    
    // Build the merkle tree (same as for transactions)
    while (hashes.size() > 1) {
        std::vector<std::string> new_hashes;
        
        for (size_t i = 0; i < hashes.size(); i += 2) {
            std::string combined;
            
            if (i + 1 < hashes.size()) {
                combined = hashes[i] + hashes[i + 1];
            } else {
                combined = hashes[i] + hashes[i]; // Duplicate the last hash if there's an odd number
            }
            
            // Use the compute_sha256 function and convert to hex
            std::string binary_hash = compute_sha256(combined);
            new_hashes.push_back(bytes_to_hex_string(binary_hash));
        }
        
        hashes = new_hashes;
    }
    
    return hashes[0];
}

bool TemplateBuilder::validate_share(const Share& share) const {
    // Check if the share header matches the current template
    std::string expected_header = current_template_.prev_hash + 
                                 current_template_.merkle_root + 
                                 std::to_string(current_template_.timestamp);
    
    if (share.header != expected_header) {
        return false;
    }
    
    // Check if the nonce is valid
    // In a real implementation, we would verify that the nonce produces a hash that meets the share target
    // For simplicity, we'll just check that the nonce is positive
    if (share.nonce < 0) {
        return false;
    }
    
    // Check if the proof is valid
    // In a real implementation, we would verify the proof
    // For simplicity, we'll just check that the proof is not empty
    if (share.proof.empty()) {
        return false;
    }
    
    return true;
}

} // namespace pocol
