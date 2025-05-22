#include <gtest/gtest.h>
#include <memory>
#include "../include/template_builder.hpp"
#include "../include/mempool.hpp"

namespace pocol {
namespace test {

class TemplateBuilderTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a mempool and template builder for testing
        mempool_ = std::make_shared<Mempool>();
        template_builder_ = std::make_shared<TemplateBuilder>(mempool_);
        
        // Add some transactions to the mempool
        for (int i = 0; i < 10; ++i) {
            Transaction tx;
            tx.txid = "txid" + std::to_string(i);
            tx.inputs.push_back("input" + std::to_string(i));
            tx.outputs.push_back("output" + std::to_string(i));
            tx.fee = 1000 + i * 100; // Different fees for sorting
            tx.timestamp = time(nullptr);
            
            mempool_->add_transaction(tx);
        }
    }

    void TearDown() override {
        // Clean up
        mempool_->clear();
    }

    std::shared_ptr<Mempool> mempool_;
    std::shared_ptr<TemplateBuilder> template_builder_;
};

TEST_F(TemplateBuilderTest, BuildTemplate) {
    // Build a template
    std::string prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    Block template_block = template_builder_->build_template(prev_block_hash);
    
    // Check the template properties
    ASSERT_EQ(template_block.prev_hash, prev_block_hash);
    ASSERT_GT(template_block.timestamp, 0);
    ASSERT_FALSE(template_block.merkle_root.empty());
    
    // Check that transactions were included
    ASSERT_GT(template_block.transactions.size(), 0);
    
    // Check that transactions are sorted by fee (highest first)
    for (size_t i = 1; i < template_block.transactions.size(); ++i) {
        ASSERT_GE(template_block.transactions[i - 1].fee, template_block.transactions[i].fee);
    }
}

TEST_F(TemplateBuilderTest, GetCurrentTemplate) {
    // Build a template
    std::string prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    Block built_template = template_builder_->build_template(prev_block_hash);
    
    // Get the current template
    Block current_template = template_builder_->get_current_template();
    
    // Check that they match
    ASSERT_EQ(current_template.prev_hash, built_template.prev_hash);
    ASSERT_EQ(current_template.timestamp, built_template.timestamp);
    ASSERT_EQ(current_template.merkle_root, built_template.merkle_root);
    ASSERT_EQ(current_template.transactions.size(), built_template.transactions.size());
}

TEST_F(TemplateBuilderTest, UpdateTemplate) {
    // Build a template
    std::string prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    Block first_template = template_builder_->build_template(prev_block_hash);
    
    // Update the template with a new previous block hash
    std::string new_prev_block_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    template_builder_->update_template(new_prev_block_hash);
    
    // Get the updated template
    Block updated_template = template_builder_->get_current_template();
    
    // Check that the template was updated
    ASSERT_EQ(updated_template.prev_hash, new_prev_block_hash);
    ASSERT_NE(updated_template.timestamp, first_template.timestamp);
}

TEST_F(TemplateBuilderTest, AddShare) {
    // Build a template
    std::string prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    Block template_block = template_builder_->build_template(prev_block_hash);
    
    // Create a share
    Share share;
    share.header = template_block.prev_hash + template_block.merkle_root + std::to_string(template_block.timestamp);
    share.nonce = 12345;
    share.proof = "proof";
    share.miner_id = "miner1";
    
    // Add the share
    bool added = template_builder_->add_share(share);
    
    // Check that the share was added
    ASSERT_TRUE(added);
    
    // Get the updated template
    Block updated_template = template_builder_->get_current_template();
    
    // Check that the share merkle root was updated
    ASSERT_FALSE(updated_template.share_merkle_root.empty());
}

TEST_F(TemplateBuilderTest, FinalizeBlock) {
    // Build a template
    std::string prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    Block template_block = template_builder_->build_template(prev_block_hash);
    
    // Add a share
    Share share;
    share.header = template_block.prev_hash + template_block.merkle_root + std::to_string(template_block.timestamp);
    share.nonce = 12345;
    share.proof = "proof";
    share.miner_id = "miner1";
    
    template_builder_->add_share(share);
    
    // Finalize the block
    int32_t nonce = 54321;
    Block finalized_block = template_builder_->finalize_block(nonce);
    
    // Check the finalized block
    ASSERT_EQ(finalized_block.nonce, nonce);
    ASSERT_FALSE(finalized_block.hash.empty());
    ASSERT_FALSE(finalized_block.share_merkle_root.empty());
    
    // Check that a new template was created
    Block new_template = template_builder_->get_current_template();
    ASSERT_EQ(new_template.prev_hash, finalized_block.hash);
}

TEST_F(TemplateBuilderTest, CreateMerkleRoot) {
    // Create transactions
    std::vector<Transaction> transactions;
    
    for (int i = 0; i < 5; ++i) {
        Transaction tx;
        tx.txid = "txid" + std::to_string(i);
        transactions.push_back(tx);
    }
    
    // Create a merkle root
    std::string merkle_root = template_builder_->create_merkle_root(transactions);
    
    // Check that the merkle root is not empty
    ASSERT_FALSE(merkle_root.empty());
    
    // Create a merkle root with different transactions
    transactions[0].txid = "different_txid";
    std::string different_merkle_root = template_builder_->create_merkle_root(transactions);
    
    // Check that the merkle roots are different
    ASSERT_NE(merkle_root, different_merkle_root);
}

TEST_F(TemplateBuilderTest, ValidateShare) {
    // Build a template
    std::string prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    Block template_block = template_builder_->build_template(prev_block_hash);
    
    // Create a valid share
    Share valid_share;
    valid_share.header = template_block.prev_hash + template_block.merkle_root + std::to_string(template_block.timestamp);
    valid_share.nonce = 12345;
    valid_share.proof = "proof";
    valid_share.miner_id = "miner1";
    
    // Create an invalid share (wrong header)
    Share invalid_share;
    invalid_share.header = "wrong_header";
    invalid_share.nonce = 12345;
    invalid_share.proof = "proof";
    invalid_share.miner_id = "miner1";
    
    // Validate the shares
    bool valid_result = template_builder_->validate_share(valid_share);
    bool invalid_result = template_builder_->validate_share(invalid_share);
    
    // Check the validation results
    ASSERT_TRUE(valid_result);
    ASSERT_FALSE(invalid_result);
}

} // namespace test
} // namespace pocol
