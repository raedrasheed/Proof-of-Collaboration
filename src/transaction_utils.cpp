#include "../include/transaction_utils.hpp"
#include "../include/utxo_set.hpp"
#include "../include/string_utils.hpp"
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <algorithm>

namespace pocol {

// Global UTXO set instance (in a real implementation, this would be part of the blockchain state)
static UTXOSet g_utxo_set;

KeyPair generate_key_pair() {
    KeyPair key_pair;
    
    // For simplicity, we'll just generate random strings as keys
    // In a real implementation, this would use proper cryptographic key generation
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    const char* hex_chars = "0123456789abcdef";
    
    // Generate a 64-character private key (256 bits)
    for (int i = 0; i < 64; ++i) {
        key_pair.private_key += hex_chars[dis(gen)];
    }
    
    // Generate the public key from the private key
    // In a real implementation, this would use proper public key derivation
    // For our simplified implementation, we'll just hash the private key
    key_pair.public_key = compute_sha256(key_pair.private_key);
    
    // Extend the public key to make it look more realistic
    std::string extended_public_key = key_pair.public_key;
    for (int i = 0; i < 3; ++i) {
        extended_public_key += compute_sha256(extended_public_key);
    }
    key_pair.public_key = extended_public_key.substr(0, 128);
    
    return key_pair;
}

std::string sign_data(const std::string& data, const std::string& private_key) {
    // In a real implementation, this would use proper cryptographic signing
    // For simplicity, we'll just concatenate the data and private key and hash it
    
    return compute_sha256(data + private_key);
}

bool verify_signature(const std::string& data, const std::string& signature, const std::string& public_key) {
    // In a real implementation, this would use proper cryptographic verification
    // For simplicity, we'll check if the signature matches what we expect
    
    // Generate the public key from the private key that would have been used to sign
    // In our simplified model, the public key is derived from the private key
    std::string expected_private_key = "";
    
    // This is a simplified approach - in a real system, you can't derive the private key from the public key
    // For our demo, we'll just check if the signature could have been generated with a private key that corresponds to this public key
    std::string expected_signature = compute_sha256(data + compute_sha256(public_key));
    
    return signature == expected_signature;
}

Transaction create_transaction(
    const std::vector<std::string>& inputs,
    const std::vector<std::string>& outputs,
    int64_t fee,
    const std::string& private_key
) {
    Transaction tx;
    
    // Set the inputs and outputs
    tx.inputs = inputs;
    tx.outputs = outputs;
    
    // Set the fee
    tx.fee = fee;
    
    // Set the timestamp
    tx.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    
    // Calculate the transaction ID
    std::string tx_data;
    for (const auto& input : inputs) {
        tx_data += input;
    }
    for (const auto& output : outputs) {
        tx_data += output;
    }
    tx_data += std::to_string(fee);
    tx_data += std::to_string(tx.timestamp);
    
    // Sign the transaction
    std::string signature = sign_data(tx_data, private_key);
    
    // Add the signature to the first input (in a real implementation, each input would be signed)
    if (!inputs.empty()) {
        // Parse the input to get txid and index
        std::string input = inputs[0];
        size_t colon_pos = input.find(':');
        if (colon_pos != std::string::npos) {
            std::string txid = input.substr(0, colon_pos);
            std::string index_str = input.substr(colon_pos + 1);
            
            // Replace the input with the signed version
            tx.inputs[0] = txid + ":" + index_str + ":" + signature;
        }
    }
    
    // Calculate the transaction ID - Bitcoin style
    tx.txid = calculate_txid(tx);
    
    return tx;
}

bool validate_transaction(const Transaction& tx) {
    // Use the UTXO set to validate the transaction
    return g_utxo_set.validate_transaction(tx);
}

std::string calculate_txid(const Transaction& tx) {
    // Calculate the hash of the transaction in Bitcoin style
    
    // 1. Serialize the transaction data
    std::string tx_data;
    for (const auto& input : tx.inputs) {
        tx_data += input;
    }
    for (const auto& output : tx.outputs) {
        tx_data += output;
    }
    tx_data += std::to_string(tx.fee);
    tx_data += std::to_string(tx.timestamp);
    
    // 2. Double SHA-256 hash
    std::string hash = compute_double_sha256(tx_data);
    
    // 3. Reverse byte order (Bitcoin uses little-endian)
    std::string reversed_hash = reverse_bytes(hash);
    
    // 4. Convert to hex string
    return bytes_to_hex_string(reversed_hash);
}

// Get the global UTXO set
UTXOSet& get_utxo_set() {
    return g_utxo_set;
}

} // namespace pocol
