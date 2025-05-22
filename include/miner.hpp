#pragma once

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include "message_types.hpp"
#include "template_builder.hpp"
#include "network.hpp"

namespace pocol {

struct Range {
    int32_t id;
    uint32_t start;
    uint32_t end;
    bool is_assigned;
    std::string assigned_to;
};

class Miner {
public:
    Miner(std::shared_ptr<Network> network, std::shared_ptr<TemplateBuilder> template_builder);
    ~Miner();

    // Start mining
    void start();
    
    // Stop mining
    void stop();
    
    // Request a range to mine
    bool request_range();
    
    // Handle a range request from another miner
    bool handle_range_request(const RangeRequest& request);
    
    // Handle a range completion notification
    void handle_range_complete(const RangeComplete& complete);
    
    // Submit a share
    bool submit_share(const Share& share);
    
    // Submit a block
    bool submit_block(const Block& block);
    
    // Get miner ID
    std::string get_miner_id() const;
    
    // Set miner ID
    void set_miner_id(const std::string& id);

    // Make these methods and members public for testing
    void mine_thread();
    std::vector<Range> calculate_ranges(const std::string& prev_block_hash);
    bool meets_target(const std::string& hash, const std::string& target) const;
    bool meets_share_target(const std::string& hash) const;
    // NEW METHOD: Check if a hash meets the block target
    bool meets_block_target(const std::string& hash) const;
    std::string double_sha256(const std::string& data) const;
    
    Range current_range_;
    std::vector<Range> ranges_;

private:
    std::shared_ptr<Network> network_;
    std::shared_ptr<TemplateBuilder> template_builder_;
    std::atomic<bool> is_running_;
    std::thread mining_thread_;
    std::string miner_id_;
    std::mutex range_mutex_;
    std::condition_variable range_cv_;
    std::string block_target_;
    std::string share_target_;
    const uint32_t RANGE_SIZE = 1000000; // Number of nonces per range
};

} // namespace pocol
