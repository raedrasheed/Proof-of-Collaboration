#include <gtest/gtest.h>
#include <memory>
#include "../include/share_manager.hpp"

namespace pocol {
namespace test {

class ShareManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a share manager for testing
        share_manager_ = std::make_shared<ShareManager>();
        
        // Create some shares
        for (int i = 0; i < 5; ++i) {
            Share share;
            share.header = "header" + std::to_string(i);
            share.nonce = i;
            share.proof = "proof" + std::to_string(i);
            share.miner_id = "miner" + std::to_string(i % 3); // 3 different miners
            
            shares_.push_back(share);
        }
    }

    void TearDown() override {
        // Clean up
        share_manager_->clear();
    }

    std::shared_ptr<ShareManager> share_manager_;
    std::vector<Share> shares_;
};

TEST_F(ShareManagerTest, AddShare) {
    // Add shares
    for (const auto& share : shares_) {
        bool added = share_manager_->add_share(share.miner_id, share);
        ASSERT_TRUE(added);
    }
    
    // Check share counts
    ASSERT_EQ(share_manager_->get_share_count("miner0"), 2); // 2 shares for miner0
    ASSERT_EQ(share_manager_->get_share_count("miner1"), 2); // 2 shares for miner1
    ASSERT_EQ(share_manager_->get_share_count("miner2"), 1); // 1 share for miner2
    ASSERT_EQ(share_manager_->get_share_count("miner3"), 0); // 0 shares for miner3
}

TEST_F(ShareManagerTest, GetShareCount) {
    // Add shares
    for (const auto& share : shares_) {
        share_manager_->add_share(share.miner_id, share);
    }
    
    // Check share counts
    ASSERT_EQ(share_manager_->get_share_count("miner0"), 2);
    ASSERT_EQ(share_manager_->get_share_count("miner1"), 2);
    ASSERT_EQ(share_manager_->get_share_count("miner2"), 1);
    
    // Check share count for a miner with no shares
    ASSERT_EQ(share_manager_->get_share_count("miner3"), 0);
}

TEST_F(ShareManagerTest, GetAllShares) {
    // Add shares
    for (const auto& share : shares_) {
        share_manager_->add_share(share.miner_id, share);
    }
    
    // Get all shares
    std::vector<Share> all_shares = share_manager_->get_all_shares();
    
    // Check that all shares were returned
    ASSERT_EQ(all_shares.size(), shares_.size());
    
    // Check that each share is in the returned list
    for (const auto& share : shares_) {
        bool found = false;
        for (const auto& returned_share : all_shares) {
            if (returned_share.header == share.header &&
                returned_share.nonce == share.nonce &&
                returned_share.proof == share.proof &&
                returned_share.miner_id == share.miner_id) {
                found = true;
                break;
            }
        }
        ASSERT_TRUE(found);
    }
}

TEST_F(ShareManagerTest, GetShareTable) {
    // Add shares
    for (const auto& share : shares_) {
        share_manager_->add_share(share.miner_id, share);
    }
    
    // Get the share table
    std::unordered_map<std::string, int32_t> share_table = share_manager_->get_share_table();
    
    // Check the share table
    ASSERT_EQ(share_table.size(), 3); // 3 miners
    ASSERT_EQ(share_table["miner0"], 2);
    ASSERT_EQ(share_table["miner1"], 2);
    ASSERT_EQ(share_table["miner2"], 1);
}

TEST_F(ShareManagerTest, Clear) {
    // Add shares
    for (const auto& share : shares_) {
        share_manager_->add_share(share.miner_id, share);
    }
    
    // Check that shares were added
    ASSERT_GT(share_manager_->get_all_shares().size(), 0);
    
    // Clear the share manager
    share_manager_->clear();
    
    // Check that all shares were removed
    ASSERT_EQ(share_manager_->get_all_shares().size(), 0);
    ASSERT_EQ(share_manager_->get_share_table().size(), 0);
    ASSERT_EQ(share_manager_->get_share_count("miner0"), 0);
}

TEST_F(ShareManagerTest, ValidateShare) {
    // Create a valid share
    Share valid_share;
    valid_share.header = "header";
    valid_share.nonce = 12345;
    valid_share.proof = "proof";
    valid_share.miner_id = "miner";
    
    // Create an invalid share (empty proof)
    Share invalid_share;
    invalid_share.header = "header";
    invalid_share.nonce = 12345;
    invalid_share.proof = "";
    invalid_share.miner_id = "miner";
    
    // Validate the shares
    bool valid_result = share_manager_->validate_share(valid_share);
    bool invalid_result = share_manager_->validate_share(invalid_share);
    
    // Check the validation results
    ASSERT_TRUE(valid_result);
    ASSERT_FALSE(invalid_result);
}

TEST_F(ShareManagerTest, CalculateRewards) {
    // Add shares
    for (const auto& share : shares_) {
        share_manager_->add_share(share.miner_id, share);
    }
    
    // Calculate rewards
    double block_reward = 50.0;
    std::unordered_map<std::string, double> rewards = share_manager_->calculate_rewards(block_reward);
    
    // Check the rewards
    ASSERT_EQ(rewards.size(), 3); // 3 miners
    
    // Check that the rewards are proportional to the share counts
    ASSERT_DOUBLE_EQ(rewards["miner0"], block_reward * 2 / 5); // 2/5 of the reward
    ASSERT_DOUBLE_EQ(rewards["miner1"], block_reward * 2 / 5); // 2/5 of the reward
    ASSERT_DOUBLE_EQ(rewards["miner2"], block_reward * 1 / 5); // 1/5 of the reward
    
    // Check that the total reward is equal to the block reward
    double total_reward = 0.0;
    for (const auto& pair : rewards) {
        total_reward += pair.second;
    }
    ASSERT_DOUBLE_EQ(total_reward, block_reward);
}

TEST_F(ShareManagerTest, CalculateRewardsWithNoShares) {
    // Calculate rewards with no shares
    double block_reward = 50.0;
    std::unordered_map<std::string, double> rewards = share_manager_->calculate_rewards(block_reward);
    
    // Check that no rewards were calculated
    ASSERT_TRUE(rewards.empty());
}

} // namespace test
} // namespace pocol
