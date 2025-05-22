#include "../include/share_manager.hpp"
#include <numeric>

namespace pocol {

ShareManager::ShareManager() {
}

ShareManager::~ShareManager() {
}

bool ShareManager::add_share(const std::string& miner_id, const Share& share) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Validate the share
    if (!validate_share(share)) {
        return false;
    }
    
    // Add the share
    miner_shares_[miner_id].push_back(share);
    
    return true;
}

int32_t ShareManager::get_share_count(const std::string& miner_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = miner_shares_.find(miner_id);
    if (it != miner_shares_.end()) {
        return it->second.size();
    }
    
    return 0;
}

std::vector<Share> ShareManager::get_all_shares() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Share> result;
    
    for (const auto& pair : miner_shares_) {
        result.insert(result.end(), pair.second.begin(), pair.second.end());
    }
    
    return result;
}

std::unordered_map<std::string, int32_t> ShareManager::get_share_table() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::unordered_map<std::string, int32_t> result;
    
    for (const auto& pair : miner_shares_) {
        result[pair.first] = pair.second.size();
    }
    
    return result;
}

void ShareManager::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    miner_shares_.clear();
}

bool ShareManager::validate_share(const Share& share) const {
    // In a real implementation, we would verify that the share meets the target
    // For simplicity, we'll just check that the proof is not empty
    return !share.proof.empty();
}

std::unordered_map<std::string, double> ShareManager::calculate_rewards(double block_reward) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::unordered_map<std::string, double> rewards;
    
    // Calculate the total number of shares
    int32_t total_shares = 0;
    for (const auto& pair : miner_shares_) {
        total_shares += pair.second.size();
    }
    
    if (total_shares == 0) {
        return rewards;
    }
    
    // Calculate the reward per share
    double reward_per_share = block_reward / total_shares;
    
    // Calculate the reward for each miner
    for (const auto& pair : miner_shares_) {
        rewards[pair.first] = pair.second.size() * reward_per_share;
    }
    
    return rewards;
}

} // namespace pocol
