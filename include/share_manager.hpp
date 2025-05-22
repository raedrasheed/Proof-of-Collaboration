#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include "message_types.hpp"

namespace pocol {

class ShareManager {
public:
    ShareManager();
    ~ShareManager();

    // Add a share for a miner
    bool add_share(const std::string& miner_id, const Share& share);
    
    // Get share count for a miner
    int32_t get_share_count(const std::string& miner_id) const;
    
    // Get all shares
    std::vector<Share> get_all_shares() const;
    
    // Get share table (miner_id -> share_count)
    std::unordered_map<std::string, int32_t> get_share_table() const;
    
    // Clear all shares
    void clear();
    
    // Validate a share
    bool validate_share(const Share& share) const;
    
    // Calculate rewards based on shares
    std::unordered_map<std::string, double> calculate_rewards(double block_reward) const;

private:
    std::unordered_map<std::string, std::vector<Share>> miner_shares_;
    mutable std::mutex mutex_;
};

} // namespace pocol
