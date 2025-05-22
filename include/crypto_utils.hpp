#pragma once

#include <string>
#include <openssl/evp.h>

namespace pocol {

// Compute SHA-256 hash using the EVP API
inline std::string compute_sha256(const std::string& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return "";
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    if (EVP_DigestUpdate(ctx, data.c_str(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    EVP_MD_CTX_free(ctx);
    
    return std::string(reinterpret_cast<char*>(hash), hash_len);
}

// Compute double SHA-256 hash
inline std::string compute_double_sha256(const std::string& data) {
    std::string first_hash = compute_sha256(data);
    return compute_sha256(first_hash);
}

} // namespace pocol
