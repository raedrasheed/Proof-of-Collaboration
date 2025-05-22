#include <gtest/gtest.h>
#include "../include/mempool.hpp"

namespace pocol {
namespace test {

class MempoolTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup code
    }

    void TearDown() override {
        // Teardown code
    }
};

TEST_F(MempoolTest, AddTransactionTest) {
    // Create a mempool instance
    Mempool mempool;
    
    // Create a transaction
    Transaction tx;
    tx.txid = "txid1";
    tx.inputs.push_back("input1");
    tx.outputs.push_back("output1");
    tx.fee = 1000;
    tx.timestamp = time(nullptr);
    
    // Add the transaction to the mempool
    bool added = mempool.add_transaction(tx);
    ASSERT_TRUE(added);
    
    // Check if the transaction exists in the mempool
    ASSERT_TRUE(mempool.has_transaction("txid1"));
    
    // Check the mempool size
    ASSERT_EQ(mempool.size(), 1);
}

TEST_F(MempoolTest, SortTransactionsTest) {
    // Create a mempool instance
    Mempool mempool;
    
    // Create transactions with different fees
    Transaction tx1;
    tx1.txid = "txid1";
    tx1.fee = 1000;
    tx1.timestamp = time(nullptr);
    
    Transaction tx2;
    tx2.txid = "txid2";
    tx2.fee = 2000;
    tx2.timestamp = time(nullptr);
    
    Transaction tx3;
    tx3.txid = "txid3";
    tx3.fee = 1500;
    tx3.timestamp = time(nullptr);
    
    // Add transactions to the mempool
    mempool.add_transaction(tx1);
    mempool.add_transaction(tx2);
    mempool.add_transaction(tx3);
    
    // Get sorted transactions
    std::vector<Transaction> sorted = mempool.get_sorted_transactions("seed");
    
    // Check if transactions are sorted by fee (highest first)
    ASSERT_EQ(sorted.size(), 3);
    ASSERT_EQ(sorted[0].txid, "txid2"); // Highest fee
    ASSERT_EQ(sorted[1].txid, "txid3"); // Medium fee
    ASSERT_EQ(sorted[2].txid, "txid1"); // Lowest fee
}

} // namespace test
} // namespace pocol
