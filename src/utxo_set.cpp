#include "../include/utxo_set.hpp"
#include <algorithm>
#include <sstream>
#include <iostream>

namespace pocol {

UTXOSet::UTXOSet() {
}

UTXOSet::~UTXOSet() {
}

bool UTXOSet::add_transaction(const Transaction& tx) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Parse outputs and add them to the UTXO set
    for (uint32_t i = 0; i < tx.outputs.size(); ++i) {
        // Parse the output string (format: "address:amount")
        std::string output = tx.outputs[i];
        size_t colon_pos = output.find(':');
        if (colon_pos == std::string::npos) {
            return false; // Invalid output format
        }
        
        std::string address = output.substr(0, colon_pos);
        int64_t amount = std::stoll(output.substr(colon_pos + 1));
        
        // Create the outpoint
        OutPoint outpoint;
        outpoint.txid = tx.txid;
        outpoint.index = i;
        
        // Create the transaction output
        TransactionOutput txout;
        txout.txid = tx.txid;
        txout.index = i;
        txout.address = address;
        txout.amount = amount;
        txout.is_spent = false;
        
        // Add to the UTXO set
        utxos_[outpoint] = txout;
        
        // Add to the address index
        address_to_utxos_[address].push_back(outpoint);
    }
    
    return true;
}

bool UTXOSet::spend_outputs(const Transaction& tx) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Parse inputs and mark the referenced outputs as spent
    for (const auto& input : tx.inputs) {
        // Parse the input string (format: "txid:index[:signature]")
        std::string input_str = input;
        size_t first_colon_pos = input_str.find(':');
        if (first_colon_pos == std::string::npos) {
            return false; // Invalid input format
        }
        
        size_t second_colon_pos = input_str.find(':', first_colon_pos + 1);
        std::string txid = input_str.substr(0, first_colon_pos);
        uint32_t index;
        
        if (second_colon_pos == std::string::npos) {
            // No signature part
            index = std::stoul(input_str.substr(first_colon_pos + 1));
        } else {
            // Has signature part
            index = std::stoul(input_str.substr(first_colon_pos + 1, second_colon_pos - first_colon_pos - 1));
        }
        
        // Create the outpoint
        OutPoint outpoint;
        outpoint.txid = txid;
        outpoint.index = index;
        
        // Check if the outpoint exists in the UTXO set
        auto it = utxos_.find(outpoint);
        if (it == utxos_.end()) {
            return false; // UTXO not found
        }
        
        // Check if the UTXO is already spent
        if (it->second.is_spent) {
            return false; // Double spend attempt
        }
        
        // Mark the UTXO as spent
        it->second.is_spent = true;
        
        // Remove from the address index
        std::string address = it->second.address;
        auto& address_utxos = address_to_utxos_[address];
        address_utxos.erase(
            std::remove_if(address_utxos.begin(), address_utxos.end(),
                [&outpoint](const OutPoint& op) {
                    return op.txid == outpoint.txid && op.index == outpoint.index;
                }),
            address_utxos.end()
        );
        
        // If the address has no more UTXOs, remove it from the map
        if (address_utxos.empty()) {
            address_to_utxos_.erase(address);
        }
    }
    
    return true;
}

bool UTXOSet::validate_transaction(const Transaction& tx) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check that the transaction has at least one input and one output
    if (tx.inputs.empty() || tx.outputs.empty()) {
        std::cerr << "Transaction validation failed: No inputs or outputs" << std::endl;
        return false;
    }
    
    // Calculate the total input amount
    int64_t total_input = 0;
    
    for (const auto& input : tx.inputs) {
        // Parse the input string (format: "txid:index[:signature]")
        std::string input_str = input;
        size_t first_colon_pos = input_str.find(':');
        if (first_colon_pos == std::string::npos) {
            std::cerr << "Transaction validation failed: Invalid input format" << std::endl;
            return false;
        }
        
        size_t second_colon_pos = input_str.find(':', first_colon_pos + 1);
        std::string txid = input_str.substr(0, first_colon_pos);
        uint32_t index;
        
        if (second_colon_pos == std::string::npos) {
            // No signature part
            index = std::stoul(input_str.substr(first_colon_pos + 1));
        } else {
            // Has signature part
            index = std::stoul(input_str.substr(first_colon_pos + 1, second_colon_pos - first_colon_pos - 1));
        }
        
        // Create the outpoint
        OutPoint outpoint;
        outpoint.txid = txid;
        outpoint.index = index;
        
        // Check if the outpoint exists in the UTXO set
        auto it = utxos_.find(outpoint);
        if (it == utxos_.end()) {
            std::cerr << "Transaction validation failed: UTXO not found - " << txid << ":" << index << std::endl;
            return false;
        }
        
        // Check if the UTXO is already spent
        if (it->second.is_spent) {
            std::cerr << "Transaction validation failed: Double spend attempt" << std::endl;
            return false;
        }
        
        // Add the amount to the total input
        total_input += it->second.amount;
    }
    
    // Calculate the total output amount
    int64_t total_output = 0;
    
    for (const auto& output : tx.outputs) {
        // Parse the output string (format: "address:amount")
        std::string output_str = output;
        size_t colon_pos = output_str.find(':');
        if (colon_pos == std::string::npos) {
            std::cerr << "Transaction validation failed: Invalid output format" << std::endl;
            return false;
        }
        
        int64_t amount = std::stoll(output_str.substr(colon_pos + 1));
        
        // Check that the amount is positive
        if (amount <= 0) {
            std::cerr << "Transaction validation failed: Invalid amount" << std::endl;
            return false;
        }
        
        // Add the amount to the total output
        total_output += amount;
    }
    
    // Check that the total input is greater than or equal to the total output
    if (total_input < total_output) {
        std::cerr << "Transaction validation failed: Insufficient funds (input: " 
                  << total_input << ", output: " << total_output << ")" << std::endl;
        return false;
    }
    
    // The difference between input and output is the fee
    int64_t fee = total_input - total_output;
    
    // Check that the fee matches the transaction fee
    if (fee != tx.fee) {
        std::cerr << "Transaction validation failed: Fee mismatch (calculated: " 
                  << fee << ", specified: " << tx.fee << ")" << std::endl;
        return false;
    }
    
    return true;
}

int64_t UTXOSet::get_balance(const std::string& address) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    int64_t balance = 0;
    
    // Find all UTXOs for the address
    auto it = address_to_utxos_.find(address);
    if (it != address_to_utxos_.end()) {
        for (const auto& outpoint : it->second) {
            auto utxo_it = utxos_.find(outpoint);
            if (utxo_it != utxos_.end() && !utxo_it->second.is_spent) {
                balance += utxo_it->second.amount;
            }
        }
    }
    
    return balance;
}

std::vector<TransactionOutput> UTXOSet::get_utxos_for_address(const std::string& address) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<TransactionOutput> result;
    
    // Find all UTXOs for the address
    auto it = address_to_utxos_.find(address);
    if (it != address_to_utxos_.end()) {
        for (const auto& outpoint : it->second) {
            auto utxo_it = utxos_.find(outpoint);
            if (utxo_it != utxos_.end() && !utxo_it->second.is_spent) {
                result.push_back(utxo_it->second);
            }
        }
    }
    
    return result;
}

TransactionOutput UTXOSet::get_utxo(const std::string& txid, uint32_t index) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    OutPoint outpoint;
    outpoint.txid = txid;
    outpoint.index = index;
    
    auto it = utxos_.find(outpoint);
    if (it != utxos_.end()) {
        return it->second;
    }
    
    // Return an empty output if not found
    return TransactionOutput();
}

bool UTXOSet::has_utxo(const std::string& txid, uint32_t index) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    OutPoint outpoint;
    outpoint.txid = txid;
    outpoint.index = index;
    
    auto it = utxos_.find(outpoint);
    return it != utxos_.end() && !it->second.is_spent;
}

size_t UTXOSet::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return utxos_.size();
}

void UTXOSet::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    utxos_.clear();
    address_to_utxos_.clear();
}

} // namespace pocol
