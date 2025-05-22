#include "../include/network.hpp"
#include <iostream>
#include <chrono>
#include <random>
#include <boost/bind/bind.hpp>
#include <boost/asio/placeholders.hpp>

namespace pocol {

// Peer implementation
Peer::Peer(boost::asio::ip::tcp::socket socket)
    : socket_(std::move(socket)), is_running_(false), read_buffer_(1024) {
}

Peer::~Peer() {
    stop();
}

void Peer::start() {
    if (is_running_) {
        return;
    }
    
    is_running_ = true;
    read_header();
}

void Peer::stop() {
    if (!is_running_) {
        return;
    }
    
    is_running_ = false;
    
    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
}

bool Peer::send_message(const NetworkMessage& message) {
    if (!is_running_) {
        return false;
    }
    
    try {
        // Serialize the message
        std::string serialized_message = serialize_network_message(message);
        
        // Prepare the header (4 bytes for message size)
        uint32_t message_size = serialized_message.size();
        std::vector<uint8_t> header(4);
        header[0] = (message_size >> 24) & 0xFF;
        header[1] = (message_size >> 16) & 0xFF;
        header[2] = (message_size >> 8) & 0xFF;
        header[3] = message_size & 0xFF;
        
        // Prepare the full message (header + serialized message)
        std::vector<uint8_t> full_message(header.begin(), header.end());
        full_message.insert(full_message.end(), serialized_message.begin(), serialized_message.end());
        
        // Send the message
        boost::asio::write(socket_, boost::asio::buffer(full_message));
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error sending message: " << e.what() << std::endl;
        stop();
        return false;
    }
}

std::string Peer::get_address() const {
    try {
        return socket_.remote_endpoint().address().to_string() + ":" + 
               std::to_string(socket_.remote_endpoint().port());
    } catch (const std::exception& e) {
        return "unknown";
    }
}

void Peer::read_header() {
    if (!is_running_) {
        return;
    }
    
    auto self = shared_from_this();
    boost::asio::async_read(
        socket_,
        boost::asio::buffer(read_buffer_.data(), 4),
        [this, self](const boost::system::error_code& error, std::size_t bytes_transferred) {
            if (error || bytes_transferred != 4) {
                std::cerr << "Error reading message header: " << error.message() << std::endl;
                stop();
                return;
            }
            
            // Parse the header to get the message size
            uint32_t message_size = 
                (static_cast<uint32_t>(read_buffer_[0]) << 24) |
                (static_cast<uint32_t>(read_buffer_[1]) << 16) |
                (static_cast<uint32_t>(read_buffer_[2]) << 8) |
                static_cast<uint32_t>(read_buffer_[3]);
            
            // Ensure the buffer is large enough
            if (read_buffer_.size() < message_size) {
                read_buffer_.resize(message_size);
            }
            
            // Read the message body
            read_body(message_size);
        }
    );
}

void Peer::read_body(uint32_t size) {
    if (!is_running_) {
        return;
    }
    
    auto self = shared_from_this();
    boost::asio::async_read(
        socket_,
        boost::asio::buffer(read_buffer_.data(), size),
        [this, self, size](const boost::system::error_code& error, std::size_t bytes_transferred) {
            if (error || bytes_transferred != size) {
                std::cerr << "Error reading message body: " << error.message() << std::endl;
                stop();
                return;
            }
            
            // Parse the message
            NetworkMessage message;
            std::string data(reinterpret_cast<char*>(read_buffer_.data()), size);
            if (!deserialize_network_message(data, message)) {
                std::cerr << "Failed to parse message" << std::endl;
                stop();
                return;
            }
            
            // Handle the message
            handle_message(message);
            
            // Continue reading
            read_header();
        }
    );
}

void Peer::handle_message(const NetworkMessage& message) {
    // This will be overridden by the Network class
}

// Network implementation
Network::Network(uint16_t port)
    : io_context_(), 
      acceptor_(io_context_, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
      is_running_(false) {
    
    // Initialize seed nodes
    seed_nodes_ = {
        "127.0.0.1:8333", // For testing, use localhost
        // Add more seed nodes here
    };
}

Network::~Network() {
    stop();
}

void Network::start() {
    if (is_running_) {
        return;
    }
    
    is_running_ = true;
    
    // Start accepting connections
    accept_connections();
    
    // Connect to seed nodes
    for (const auto& seed : seed_nodes_) {
        size_t colon_pos = seed.find(':');
        if (colon_pos != std::string::npos) {
            std::string host = seed.substr(0, colon_pos);
            uint16_t port = std::stoi(seed.substr(colon_pos + 1));
            connect_to_peer(host, port);
        }
    }
    
    // Start the io_context in a separate thread
    std::thread([this]() {
        try {
            io_context_.run();
        } catch (const std::exception& e) {
            std::cerr << "Error in io_context: " << e.what() << std::endl;
        }
    }).detach();
}

void Network::stop() {
    if (!is_running_) {
        return;
    }
    
    is_running_ = false;
    
    // Stop accepting connections
    boost::system::error_code ec;
    acceptor_.close(ec);
    
    // Stop all peers
    for (auto& peer : peers_) {
        peer->stop();
    }
    peers_.clear();
    
    // Stop the io_context
    io_context_.stop();
}

bool Network::broadcast_message(const NetworkMessage& message) {
    if (!is_running_ || peers_.empty()) {
        return false;
    }
    
    bool success = true;
    for (auto& peer : peers_) {
        if (!peer->send_message(message)) {
            success = false;
        }
    }
    
    return success;
}

void Network::register_message_handler(MessageType type, 
                                      std::function<void(const NetworkMessage&, std::shared_ptr<Peer>)> handler) {
    message_handlers_[type] = handler;
}

bool Network::connect_to_peer(const std::string& address, uint16_t port) {
    if (!is_running_) {
        return false;
    }
    
    try {
        // Create a resolver
        boost::asio::ip::tcp::resolver resolver(io_context_);
        
        // Resolve the endpoint using the newer API
        boost::system::error_code ec;
        auto endpoints = resolver.resolve(address, std::to_string(port), ec);
        
        if (ec) {
            std::cerr << "Failed to resolve peer address: " << ec.message() << std::endl;
            return false;
        }
        
        // Create a socket
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context_);
        
        // Connect to the endpoint
        boost::asio::async_connect(
            *socket,
            endpoints,
            [this, socket](const boost::system::error_code& error, const boost::asio::ip::tcp::endpoint& endpoint) {
                if (error) {
                    std::cerr << "Failed to connect to peer: " << error.message() << std::endl;
                    return;
                }
                
                // Create a new peer
                auto peer = std::make_shared<Peer>(std::move(*socket));
                
                // Add the peer to the list
                peers_.push_back(peer);
                
                // Start the peer
                peer->start();
                
                // Send a VERSION message
                NetworkMessage message;
                message.type = MessageType::VERSION;
                
                Version version;
                version.version = 1;
                version.user_agent = "pocol";
                version.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                
                // Generate a random nonce
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<int32_t> dis(0, std::numeric_limits<int32_t>::max());
                version.nonce = dis(gen);
                
                message.version = version;
                
                peer->send_message(message);
            }
        );
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error connecting to peer: " << e.what() << std::endl;
        return false;
    }
}

std::vector<std::string> Network::get_connected_peers() const {
    std::vector<std::string> result;
    for (const auto& peer : peers_) {
        result.push_back(peer->get_address());
    }
    return result;
}

void Network::accept_connections() {
    if (!is_running_) {
        return;
    }
    
    acceptor_.async_accept(
        [this](const boost::system::error_code& error, boost::asio::ip::tcp::socket socket) {
            if (error) {
                std::cerr << "Error accepting connection: " << error.message() << std::endl;
            } else {
                handle_new_connection(error, std::move(socket));
            }
            
            // Continue accepting connections
            accept_connections();
        }
    );
}

void Network::handle_new_connection(const boost::system::error_code& error, boost::asio::ip::tcp::socket socket) {
    if (error) {
        std::cerr << "Error handling new connection: " << error.message() << std::endl;
        return;
    }
    
    // Create a new peer
    auto peer = std::make_shared<Peer>(std::move(socket));
    
    // Add the peer to the list
    peers_.push_back(peer);
    
    // Start the peer
    peer->start();
}

} // namespace pocol
