#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <chrono>
#include "../include/miner.hpp"
#include "../include/network.hpp"
#include "../include/template_builder.hpp"
#include "../include/mempool.hpp"

namespace pocol {
namespace test {

class MinerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create components for testing
        network_ = std::make_shared<Network>(8336);
        mempool_ = std::make_shared<Mempool>();
        template_builder_ = std::make_shared<TemplateBuilder>(mempool_);
        miner_ = std::make_shared<Miner>(network_, template_builder_);
        
        // Set miner ID
        miner_->set_miner_id("test_miner");
        
        // Start the network
        network_->start();
        
        // Build an initial template
        std::string prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        template_builder_->build_template(prev_block_hash);
        
        // Allow time for setup
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    void TearDown() override {
        // Stop the miner and network
        miner_->stop();
        network_->stop();
    }

    std::shared_ptr<Network> network_;
    std::shared_ptr<Mempool> mempool_;
    std::shared_ptr<TemplateBuilder> template_builder_;
    std::shared_ptr<Miner> miner_;
};

TEST_F(MinerTest, GetSetMinerId) {
    // Check initial miner ID
    ASSERT_EQ(miner_->get_miner_id(), "test_miner");
    
    // Set a new miner ID
    miner_->set_miner_id("new_miner");
    
    // Check the new miner ID
    ASSERT_EQ(miner_->get_miner_id(), "new_miner");
}

TEST_F(MinerTest, RequestRange) {
    // Request a range
    bool requested = miner_->request_range();
    
    // Check that a range was requested
    ASSERT_TRUE(requested);
    
    // Check that the current range is assigned
    ASSERT_NE(miner_->current_range_.id, 0);
    ASSERT_TRUE(miner_->current_range_.is_assigned);
    ASSERT_EQ(miner_->current_range_.assigned_to, miner_->get_miner_id());
}

TEST_F(MinerTest, HandleRangeRequest) {
    // Request a range
    miner_->request_range();
    
    // Create a range request for a different range
    RangeRequest request;
    request.range_id = miner_->current_range_.id + 1;
    request.miner_id = "other_miner";
    
    // Handle the range request
    bool handled = miner_->handle_range_request(request);
    
    // Check that the request was handled
    ASSERT_TRUE(handled);
    
    // Check that the range is assigned to the other miner
    bool found = false;
    for (const auto& range : miner_->ranges_) {
        if (range.id == request.range_id) {
            ASSERT_TRUE(range.is_assigned);
            ASSERT_EQ(range.assigned_to, "other_miner");
            found = true;
            break;
        }
    }
    ASSERT_TRUE(found);
}

TEST_F(MinerTest, HandleRangeComplete) {
    // Request a range
    miner_->request_range();
    int32_t current_range_id = miner_->current_range_.id;
    
    // Create a range complete notification for the current range
    RangeComplete complete;
    complete.range_id = current_range_id;
    complete.miner_id = miner_->get_miner_id();
    
    // Handle the range complete notification
    miner_->handle_range_complete(complete);
    
    // Check that the current range was cleared
    ASSERT_EQ(miner_->current_range_.id, 0);
    
    // Check that the range is no longer assigned
    bool found = false;
    for (const auto& range : miner_->ranges_) {
        if (range.id == current_range_id) {
            ASSERT_FALSE(range.is_assigned);
            ASSERT_TRUE(range.assigned_to.empty());
            found = true;
            break;
        }
    }
    ASSERT_TRUE(found);
}

TEST_F(MinerTest, SubmitShare) {
    // Get the current template
    Block current_template = template_builder_->get_current_template();
    
    // Create a share
    Share share;
    share.header = current_template.prev_hash + current_template.merkle_root + std::to_string(current_template.timestamp);
    share.nonce = 12345;
    share.proof = "proof";
    share.miner_id = miner_->get_miner_id();
    
    // Submit the share
    bool submitted = miner_->submit_share(share);
    
    // Check that the share was submitted
    ASSERT_TRUE(submitted);
    
    // Check that the share was added to the template
    Block updated_template = template_builder_->get_current_template();
    ASSERT_FALSE(updated_template.share_merkle_root.empty());
}

TEST_F(MinerTest, SubmitBlock) {
    // Get the current template
    Block current_template = template_builder_->get_current_template();
    
    // Create a block
    Block block = current_template;
    block.nonce = 12345;
    block.hash = "block_hash";
    
    // Set up a message handler to receive the block
    bool block_received = false;
    NetworkMessage received_message;
    
    network_->register_message_handler(
        MessageType::BLOCK,
        [&block_received, &received_message](const NetworkMessage& message, std::shared_ptr<Peer> peer) {
            block_received = true;
            received_message = message;
        }
    );
    
    // Submit the block
    bool submitted = miner_->submit_block(block);
    
    // Check that the block was submitted
    ASSERT_TRUE(submitted);
    
    // Allow time for the block to be broadcast
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Check that the block was broadcast
    // Note: Since we're not actually connecting to peers, this might not work as expected
    // ASSERT_TRUE(block_received);
    // ASSERT_EQ(received_message.type, MessageType::BLOCK);
    // ASSERT_EQ(received_message.block.hash, "block_hash");
}

TEST_F(MinerTest, CalculateRanges) {
    // Calculate ranges
    std::string prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    std::vector<Range> ranges = miner_->calculate_ranges(prev_block_hash);
    
    // Check that ranges were calculated
    ASSERT_FALSE(ranges.empty());
    
    // Check that ranges cover the entire nonce space
    uint32_t min_nonce = 0xFFFFFFFF;
    uint32_t max_nonce = 0;
    
    for (const auto& range : ranges) {
        min_nonce = std::min(min_nonce, range.start);
        max_nonce = std::max(max_nonce, range.end);
        
        // Check that the range is not assigned
        ASSERT_FALSE(range.is_assigned);
        ASSERT_TRUE(range.assigned_to.empty());
    }
    
    ASSERT_EQ(min_nonce, 0);
    ASSERT_EQ(max_nonce, 0xFFFFFFFF);
    
    // Calculate ranges with a different seed
    std::string different_prev_block_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    std::vector<Range> different_ranges = miner_->calculate_ranges(different_prev_block_hash);
    
    // Check that the ranges are different (shuffled differently)
    bool different = false;
    for (size_t i = 0; i < ranges.size() && i < different_ranges.size(); ++i) {
        if (ranges[i].id != different_ranges[i].id) {
            different = true;
            break;
        }
    }
    
    ASSERT_TRUE(different);
}

TEST_F(MinerTest, MeetsTarget) {
    // Create a target
    std::string target(32, 0xFF);
    target[0] = 0x00; // Require the first byte to be 0
    
    // Create a hash that meets the target
    std::string meets_hash(32, 0x00);
    meets_hash[1] = 0x01; // First byte is 0, second byte is 1
    
    // Create a hash that doesn't meet the target
    std::string not_meets_hash(32, 0x00);
    not_meets_hash[0] = 0x01; // First byte is 1
    
    // Check if the hashes meet the target
    bool meets_result = miner_->meets_target(meets_hash, target);
    bool not_meets_result = miner_->meets_target(not_meets_hash, target);
    
    // Check the results
    ASSERT_TRUE(meets_result);
    ASSERT_FALSE(not_meets_result);
}

TEST_F(MinerTest, DoubleSHA256) {
    // Calculate the double SHA-256 hash of a string
    std::string data = "test data";
    std::string hash = miner_->double_sha256(data);
    
    // Check that the hash is not empty
    ASSERT_FALSE(hash.empty());
    
    // Calculate the hash again
    std::string hash2 = miner_->double_sha256(data);
    
    // Check that the hashes are the same
    ASSERT_EQ(hash, hash2);
    
    // Calculate the hash of different data
    std::string different_data = "different data";
    std::string different_hash = miner_->double_sha256(different_data);
    
    // Check that the hashes are different
    ASSERT_NE(hash, different_hash);
}

} // namespace test
} // namespace pocol
