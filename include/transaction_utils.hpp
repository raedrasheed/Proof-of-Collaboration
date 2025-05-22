#pragma once

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "message_types.hpp"
#include "crypto_utils.hpp"

namespace pocol {

// Forward declaration
class UTXOSet;

// Simple key pair structure
struct KeyPair {
    std::string private_key;
    std::string public_key;
};

// Generate a new key pair
KeyPair generate_key_pair();

// Sign data with a private key
std::string sign_data(const std::string& data, const std::string& private_key);

// Verify a signature with a public key
bool verify_signature(const std::string& data, const std::string& signature, const std::string& public_key);

// Create a new transaction
Transaction create_transaction(
    const std::vector<std::string>& inputs,
    const std::vector<std::string>& outputs,
    int64_t fee,
    const std::string& private_key
);

// Validate a transaction
bool validate_transaction(const Transaction& tx);

// Calculate the transaction ID (hash of the transaction)
std::string calculate_txid(const Transaction& tx);

// Get the global UTXO set
UTXOSet& get_utxo_set();

} // namespace pocol
