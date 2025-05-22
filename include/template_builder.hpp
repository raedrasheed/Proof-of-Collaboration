#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <memory> // Add this for std::shared_ptr
#include "message_types.hpp"
#include "mempool.hpp"

namespace pocol {

class TemplateBuilder {
public:
    TemplateBuilder(std::shared_ptr<Mempool> mempool);
    ~TemplateBuilder();

    // Build a new block template using the previous block hash as seed
    Block build_template(const std::string& prev_block_hash);
    
    // Get the current block template
    Block get_current_template() const;
    
    // Update the current template with new transactions or a new seed
    void update_template(const std::string& prev_block_hash);
    
    // Add a share to the current template
    bool add_share(const Share& share);
    
    // Finalize the block with a valid nonce
    Block finalize_block(int32_t nonce);

    // Get the mempool
    std::shared_ptr<Mempool> get_mempool() const {
        return mempool_;
    }

    // Make these methods public for testing
    std::string create_merkle_root(const std::vector<Transaction>& transactions) const;
    std::string create_share_merkle_root(const std::vector<Share>& shares) const;
    bool validate_share(const Share& share) const;

private:
    std::shared_ptr<Mempool> mempool_;
    Block current_template_;
    std::vector<Share> shares_;
    mutable std::mutex mutex_;
    const size_t MAX_BLOCK_SIZE = 1024 * 1024; // 1 MiB
};

} // namespace pocol
