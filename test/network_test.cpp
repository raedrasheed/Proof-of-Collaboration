#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <chrono>
#include "../include/network.hpp"

namespace pocol {
namespace test {

class NetworkTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a network instance for testing
        network1_ = std::make_shared<Network>(8334);
        network2_ = std::make_shared<Network>(8335);
        
        // Start the networks
        network1_->start();
        network2_->start();
        
        // Allow time for networks to start
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    void TearDown() override {
        // Stop the networks
        network1_->stop();
        network2_->stop();
    }

    std::shared_ptr<Network> network1_;
    std::shared_ptr<Network> network2_;
};

TEST_F(NetworkTest, ConnectToPeer) {
    // Connect network1 to network2
    bool connected = network1_->connect_to_peer("127.0.0.1", 8335);
    
    // Allow time for connection to establish
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Check if connection was successful
    ASSERT_TRUE(connected);
    
    // Check if network1 has network2 as a peer
    auto peers = network1_->get_connected_peers();
    ASSERT_FALSE(peers.empty());
    
    // Note: In a real test, we would verify that the peer's address matches,
    // but since we're using localhost, the exact address might vary
}

TEST_F(NetworkTest, MessageBroadcast) {
    // Connect network1 to network2
    network1_->connect_to_peer("127.0.0.1", 8335);
    
    // Allow time for connection to establish
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Set up a message handler on network2 to receive the message
    bool message_received = false;
    NetworkMessage received_message;
    
    network2_->register_message_handler(
        MessageType::VERSION,
        [&message_received, &received_message](const NetworkMessage& message, std::shared_ptr<Peer> peer) {
            message_received = true;
            received_message = message;
        }
    );
    
    // Create a message to broadcast
    NetworkMessage message;
    message.type = MessageType::VERSION;
    
    Version version;
    version.version = 1;
    version.user_agent = "test";
    version.timestamp = time(nullptr);
    version.nonce = 12345;
    
    message.version = version;
    
    // Broadcast the message from network1
    bool broadcast = network1_->broadcast_message(message);
    ASSERT_TRUE(broadcast);
    
    // Allow time for message to be received
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Check if network2 received the message
    ASSERT_TRUE(message_received);
    ASSERT_EQ(received_message.type, MessageType::VERSION);
    ASSERT_EQ(received_message.version.version, 1);
    ASSERT_EQ(received_message.version.user_agent, "test");
    ASSERT_EQ(received_message.version.nonce, 12345);
}

TEST_F(NetworkTest, PeerDisconnection) {
    // Connect network1 to network2
    network1_->connect_to_peer("127.0.0.1", 8335);
    
    // Allow time for connection to establish
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Check initial connection
    auto initial_peers = network1_->get_connected_peers();
    ASSERT_FALSE(initial_peers.empty());
    
    // Stop network2
    network2_->stop();
    
    // Allow time for disconnection to be detected
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Check if network1 has removed network2 as a peer
    // Note: This test might be flaky depending on how quickly disconnections are detected
    auto final_peers = network1_->get_connected_peers();
    ASSERT_TRUE(final_peers.empty());
}

TEST_F(NetworkTest, MessageHandlerRegistration) {
    // Create a message handler
    bool handler_called = false;
    
    network1_->register_message_handler(
        MessageType::VERSION,
        [&handler_called](const NetworkMessage& message, std::shared_ptr<Peer> peer) {
            handler_called = true;
        }
    );
    
    // Create a peer that will call the handler
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket(io_context);
    
    // Note: In a real test, we would connect the socket and send a message,
    // but for simplicity, we'll just create a peer and call the handler directly
    auto peer = std::make_shared<Peer>(std::move(socket));
    
    // Create a message
    NetworkMessage message;
    message.type = MessageType::VERSION;
    
    // Call the handler
    auto handlers = network1_->message_handlers_;
    auto it = handlers.find(MessageType::VERSION);
    ASSERT_NE(it, handlers.end());
    it->second(message, peer);
    
    // Check if handler was called
    ASSERT_TRUE(handler_called);
}

} // namespace test
} // namespace pocol
