#include "../include/miner.hpp"
#include "../include/crypto_utils.hpp"
#include <openssl/sha.h>
#include <random>
#include <algorithm>
#include <iostream>
#include <chrono>

namespace pocol {

Miner::Miner(std::shared_ptr<Network> network, std::shared_ptr<TemplateBuilder> template_builder)
    : network_(network), template_builder_(template_builder), is_running_(false), miner_id_("miner") {
    
    // Set the block target (difficulty)
    // In a real implementation, this would be adjusted based on the network hash rate
    // For simplicity, we'll use a fixed target
    block_target_ = std::string(32, 0xFF);
    block_target_[0] = 0x00; // Require the first byte to be 0
    
    // Set the share target (easier than block target)
    share_target_ = std::string(32, 0xFF);
    share_target_[0] = 0x00;
    share_target_[1] = 0x00; // Require the first two bytes to be 0
    
    // Register message handlers
    network_->register_message_handler(
        MessageType::RANGE_REQUEST,
        [this](const NetworkMessage& message, std::shared_ptr<Peer> peer) {
            handle_range_request(message.range_request);
        }
    );
    
    network_->register_message_handler(
        MessageType::RANGE_COMPLETE,
        [this](const NetworkMessage& message, std::shared_ptr<Peer> peer) {
            handle_range_complete(message.range_complete);
        }
    );
    
    network_->register_message_handler(
        MessageType::SHARE,
        [this](const NetworkMessage& message, std::shared_ptr<Peer> peer) {
            submit_share(message.share);
        }
    );
    
    network_->register_message_handler(
        MessageType::BLOCK,
        [this](const NetworkMessage& message, std::shared_ptr<Peer> peer) {
            // When a new block is received, update the template
            template_builder_->update_template(message.block.hash);
        }
    );
}

Miner::~Miner() {
    stop();
}

void Miner::start() {
    if (is_running_) {
        return;
    }
    
    is_running_ = true;
    
    // Start the mining thread
    mining_thread_ = std::thread(&Miner::mine_thread, this);
}

void Miner::stop() {
    if (!is_running_) {
        return;
    }
    
    is_running_ = false;
    
    // Notify the mining thread to stop
    range_cv_.notify_all();
    
    // Wait for the mining thread to finish
    if (mining_thread_.joinable()) {
        mining_thread_.join();
    }
}

bool Miner::request_range() {
    std::lock_guard<std::mutex> lock(range_mutex_);
    
    // Get the current template
    Block current_template = template_builder_->get_current_template();
    
    // Calculate ranges based on the previous block hash
    ranges_ = calculate_ranges(current_template.prev_hash);
    
    // Find the first unassigned range
    for (auto& range : ranges_) {
        if (!range.is_assigned) {
            // Assign the range to this miner
            range.is_assigned = true;
            range.assigned_to = miner_id_;
            current_range_ = range;
            
            // Broadcast a range request
            NetworkMessage message;
            message.type = MessageType::RANGE_REQUEST;
            
            RangeRequest request;
            request.range_id = range.id;
            request.miner_id = miner_id_;
            
            message.range_request = request;
            
            network_->broadcast_message(message);
            
            // Notify the mining thread
            range_cv_.notify_all();
            
            return true;
        }
    }
    
    return false;
}

bool Miner::handle_range_request(const RangeRequest& request) {
    std::lock_guard<std::mutex> lock(range_mutex_);
    
    // Find the range
    for (auto& range : ranges_) {
        if (range.id == request.range_id) {
            // Check if the range is already assigned
            if (range.is_assigned) {
                // If it's assigned to this miner, release it
                if (range.assigned_to == miner_id_) {
                    range.is_assigned = false;
                    range.assigned_to = "";
                    
                    // If it's the current range, stop mining it
                    if (current_range_.id == range.id) {
                        current_range_ = Range();
                        range_cv_.notify_all();
                    }
                }
                
                return false;
            }
            
            // Assign the range
            range.is_assigned = true;
            range.assigned_to = request.miner_id;
            
            return true;
        }
    }
    
    return false;
}

void Miner::handle_range_complete(const RangeComplete& complete) {
    std::lock_guard<std::mutex> lock(range_mutex_);
    
    // Find the range
    for (auto& range : ranges_) {
        if (range.id == complete.range_id) {
            // Mark the range as completed
            range.is_assigned = false;
            range.assigned_to = "";
            
            // If it's the current range, stop mining it
            if (current_range_.id == range.id) {
                current_range_ = Range();
                range_cv_.notify_all();
            }
            
            break;
        }
    }
    
    // Request a new range
    request_range();
}

bool Miner::submit_share(const Share& share) {
    // Add the share to the template
    return template_builder_->add_share(share);
}

bool Miner::submit_block(const Block& block) {
    // Broadcast the block
    NetworkMessage message;
    message.type = MessageType::BLOCK;
    message.block = block;
    
    return network_->broadcast_message(message);
}

std::string Miner::get_miner_id() const {
    return miner_id_;
}

void Miner::set_miner_id(const std::string& id) {
    miner_id_ = id;
}

void Miner::mine_thread() {
    while (is_running_) {
        // Wait for a range to be assigned
        std::unique_lock<std::mutex> lock(range_mutex_);
        range_cv_.wait(lock, [this] { 
            return !is_running_ || (current_range_.id != 0 && current_range_.is_assigned); 
        });
        
        if (!is_running_) {
            break;
        }
        
        // Get the current template
        Block current_template = template_builder_->get_current_template();
        
        // Create the header
        std::string header = current_template.prev_hash + 
                            current_template.merkle_root + 
                            std::to_string(current_template.timestamp);
        
        // Mine the range
        for (uint32_t nonce = current_range_.start; nonce < current_range_.end && is_running_; ++nonce) {
            // Check if the template has changed
            Block new_template = template_builder_->get_current_template();
            if (new_template.prev_hash != current_template.prev_hash ||
                new_template.merkle_root != current_template.merkle_root ||
                new_template.timestamp != current_template.timestamp) {
                // Template has changed, stop mining this range
                break;
            }
            
            // Calculate the hash
            std::string hash = double_sha256(header + std::to_string(nonce));
            
            // Check if the hash meets the block target
            if (meets_block_target(hash)) {
                // Found a block!
                Block block = template_builder_->finalize_block(nonce);
                submit_block(block);
                
                // Request a new range
                current_range_ = Range();
                request_range();
                break;
            }
            
            // Check if the hash meets the share target
            if (meets_share_target(hash)) {
                // Found a share!
                Share share;
                share.header = header;
                share.nonce = nonce;
                share.proof = hash;
                share.miner_id = miner_id_;
                
                submit_share(share);
            }
        }
        
        // Completed the range
        if (is_running_ && current_range_.id != 0) {
            // Broadcast a range complete message
            NetworkMessage message;
            message.type = MessageType::RANGE_COMPLETE;
            
            RangeComplete complete;
            complete.range_id = current_range_.id;
            complete.miner_id = miner_id_;
            
            message.range_complete = complete;
            
            network_->broadcast_message(message);
            
            // Request a new range
            current_range_ = Range();
            request_range();
        }
    }
}

std::vector<Range> Miner::calculate_ranges(const std::string& prev_block_hash) {
    std::vector<Range> ranges;
    
    // Calculate the number of ranges
    uint32_t num_ranges = 0xFFFFFFFF / RANGE_SIZE;
    
    // Create the ranges
    for (uint32_t i = 0; i < num_ranges; ++i) {
        Range range;
        range.id = i + 1;
        range.start = i * RANGE_SIZE;
        range.end = (i + 1) * RANGE_SIZE;
        range.is_assigned = false;
        range.assigned_to = "";
        
        ranges.push_back(range);
    }
    
    // Add the last range
    if (num_ranges * RANGE_SIZE < 0xFFFFFFFF) {
        Range range;
        range.id = num_ranges + 1;
        range.start = num_ranges * RANGE_SIZE;
        range.end = 0xFFFFFFFF;
        range.is_assigned = false;
        range.assigned_to = "";
        
        ranges.push_back(range);
    }
    
    // Shuffle the ranges based on the previous block hash
    std::seed_seq seed(prev_block_hash.begin(), prev_block_hash.end());
    std::mt19937 gen(seed);
    std::shuffle(ranges.begin(), ranges.end(), gen);
    
    return ranges;
}

bool Miner::meets_target(const std::string& hash, const std::string& target) const {
    // Compare the hash with the target
    // The hash must be less than the target
    return hash < target;
}

bool Miner::meets_block_target(const std::string& hash) const {
    // Use the meets_target method with the block_target_
    return meets_target(hash, block_target_);
}

bool Miner::meets_share_target(const std::string& hash) const {
    // Compare the hash with the share target
    return meets_target(hash, share_target_);
}

std::string Miner::double_sha256(const std::string& data) const {
    // Use the compute_double_sha256 function from crypto_utils.hpp
    return compute_double_sha256(data);
}

} // namespace pocol
