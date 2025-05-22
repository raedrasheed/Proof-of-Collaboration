#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <boost/asio.hpp>
#include "message_types.hpp"

namespace pocol {

class Peer : public std::enable_shared_from_this<Peer> {
public:
    Peer(boost::asio::ip::tcp::socket socket);
    ~Peer();

    void start();
    void stop();
    bool send_message(const NetworkMessage& message);
    std::string get_address() const;

private:
    void read_header();
    void read_body(uint32_t size);
    void handle_message(const NetworkMessage& message);

    boost::asio::ip::tcp::socket socket_;
    bool is_running_;
    std::vector<uint8_t> read_buffer_;
};

class Network {
public:
    Network(uint16_t port);
    ~Network();

    void start();
    void stop();
    bool broadcast_message(const NetworkMessage& message);
    void register_message_handler(MessageType type, 
                                 std::function<void(const NetworkMessage&, std::shared_ptr<Peer>)> handler);
    bool connect_to_peer(const std::string& address, uint16_t port);
    std::vector<std::string> get_connected_peers() const;

    // Make message_handlers_ public for testing
    std::unordered_map<MessageType, 
                      std::function<void(const NetworkMessage&, std::shared_ptr<Peer>)>> message_handlers_;

private:
    void accept_connections();
    void handle_new_connection(const boost::system::error_code& error, boost::asio::ip::tcp::socket socket);

    boost::asio::io_context io_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::vector<std::shared_ptr<Peer>> peers_;
    bool is_running_;
    std::vector<std::string> seed_nodes_;
};

} // namespace pocol
