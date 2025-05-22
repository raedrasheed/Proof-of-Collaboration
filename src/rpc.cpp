#include "../include/rpc.hpp"
#include "../include/transaction_utils.hpp"
#include "../include/utxo_set.hpp"
#include "../include/string_utils.hpp"
#include "../include/crypto_utils.hpp"
#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <thread>
#include <memory>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>

namespace pocol {

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace pt = boost::property_tree;
using tcp = net::ip::tcp;

// Global set to track all addresses seen by the system
static std::unordered_set<std::string> g_all_addresses;

// Transaction history storage
static std::unordered_map<std::string, Transaction> g_transaction_history;

// Registered miners storage - now just a set of public keys
static std::unordered_set<std::string> g_registered_miners;

RPC::RPC(uint16_t port, 
         std::shared_ptr<TemplateBuilder> template_builder,
         std::shared_ptr<Miner> miner,
         std::shared_ptr<ShareManager> share_manager)
    : io_context_(), 
      acceptor_(io_context_, tcp::endpoint(tcp::v4(), port)),
      template_builder_(template_builder),
      miner_(miner),
      share_manager_(share_manager),
      is_running_(false) {
    
    // Register RPC methods
    rpc_methods_["getpocoltemplate"] = [this](const std::string& params) {
        return get_pocol_template();
    };
    
    rpc_methods_["requestpocolrange"] = [this](const std::string& params) {
        return request_pocol_range(params);
    };
    
    rpc_methods_["submitpocolshare"] = [this](const std::string& params) {
        return submit_pocol_share(params);
    };
    
    rpc_methods_["getpocolbalance"] = [this](const std::string& params) {
        return get_pocol_balance(params);
    };
    
    rpc_methods_["createpocoltransaction"] = [this](const std::string& params) {
        return create_pocol_transaction(params);
    };
    
    rpc_methods_["getpocoltransaction"] = [this](const std::string& params) {
        return get_pocol_transaction(params);
    };
    
    rpc_methods_["getpocolutxos"] = [this](const std::string& params) {
        return get_pocol_utxos(params);
    };
    
    rpc_methods_["getpocolutxo"] = [this](const std::string& params) {
        return get_pocol_utxo(params);
    };
    
    rpc_methods_["createcoinbase"] = [this](const std::string& params) {
        return create_coinbase_transaction(params);
    };
    
    rpc_methods_["registerpocolminer"] = [this](const std::string& params) {
        return register_pocol_miner(params);
    };
    
    rpc_methods_["getpocolrewards"] = [this](const std::string& params) {
        return get_pocol_rewards(params);
    };
    
    rpc_methods_["getpocolminers"] = [this](const std::string& params) {
        return get_pocol_miners(params);
    };
    
    rpc_methods_["completepocolrange"] = [this](const std::string& params) {
        return complete_pocol_range(params);
    };
    
    // Initialize with some default addresses
    g_all_addresses.insert("e707f705f7cabd3a00e12eca0b96f66be707f705f7cabd3a00e12eca0b96f66be707f705f7cabd3a00e12eca0b96f66be707f705f7cabd3a00e12eca0b96f66b");
    g_all_addresses.insert("bcc4a36d6821c0988ee68f600581c310bcc4a36d6821c0988ee68f600581c310bcc4a36d6821c0988ee68f600581c310bcc4a36d6821c0988ee68f600581c310");
    
    // Register a default miner (using public key as miner_id)
    g_registered_miners.insert("e707f705f7cabd3a00e12eca0b96f66be707f705f7cabd3a00e12eca0b96f66be707f705f7cabd3a00e12eca0b96f66be707f705f7cabd3a00e12eca0b96f66b");
}

RPC::~RPC() {
    stop();
}

void RPC::start() {
    if (is_running_) {
        return;
    }
    
    is_running_ = true;
    
    // Start accepting connections
    accept_connections();
    
    // Start the io_context in a separate thread
    std::thread([this]() {
        try {
            io_context_.run();
        } catch (const std::exception& e) {
            std::cerr << "Error in io_context: " << e.what() << std::endl;
        }
    }).detach();
}

void RPC::stop() {
    if (!is_running_) {
        return;
    }
    
    is_running_ = false;
    
    // Stop accepting connections
    beast::error_code ec;
    acceptor_.close(ec);
    
    // Stop the io_context
    io_context_.stop();
}

void RPC::handle_request(http::request<http::string_body>& req, http::response<http::string_body>& res) {
    // Set the response headers
    res.set(http::field::server, "pocol-rpc");
    res.set(http::field::content_type, "application/json");
    res.set(http::field::access_control_allow_origin, "*");  // Allow CORS
    
    try {
        // Parse the JSON-RPC request
        std::string method;
        std::string params;
        int id;
        
        if (!parse_json_rpc(req.body(), method, params, id)) {
            // Invalid JSON-RPC request
            res.result(http::status::bad_request);
            res.body() = R"({"error": "Invalid JSON-RPC request", "id": null})";
            return;
        }
        
        // Find the RPC method
        auto it = rpc_methods_.find(method);
        if (it == rpc_methods_.end()) {
            // Method not found
            res.result(http::status::not_found);
            res.body() = R"({"error": "Method not found", "id": )" + std::to_string(id) + "}";
            return;
        }
        
        // Call the RPC method
        try {
            std::string result = it->second(params);
            res.result(http::status::ok);
            
            // Check if the result is already a JSON object
            if (result.empty() || result[0] != '{') {
                res.body() = R"({"result": )" + result + R"(, "id": )" + std::to_string(id) + "}";
            } else {
                // Result is already a JSON object, just wrap it with id
                res.body() = result;
            }
        } catch (const std::exception& e) {
            // Error executing the method
            res.result(http::status::internal_server_error);
            res.body() = R"({"error": ")" + std::string(e.what()) + R"(", "id": )" + std::to_string(id) + "}";
        }
    } catch (const std::exception& e) {
        // Unexpected error
        res.result(http::status::internal_server_error);
        res.body() = R"({"error": "Internal server error", "id": null})";
    }
}

bool RPC::parse_json_rpc(const std::string& body, std::string& method, std::string& params, int& id) {
    try {
        // Parse the JSON
        std::stringstream ss(body);
        pt::ptree json;
        pt::read_json(ss, json);
        
        // Check if it's a valid JSON-RPC request
        if (json.get<std::string>("jsonrpc", "") != "2.0") {
            return false;
        }
        
        // Get the method
        method = json.get<std::string>("method");
        
        // Get the params
        params = json.get<std::string>("params", "");
        
        // Get the id
        id = json.get<int>("id");
        
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

std::string RPC::get_pocol_template() {
    // Get the current template
    Block template_block = template_builder_->get_current_template();
    
    // Convert the template to JSON
    pt::ptree json;
    json.put("prev_hash", template_block.prev_hash);
    json.put("merkle_root", template_block.merkle_root);
    json.put("timestamp", template_block.timestamp);
    
    // Add transactions
    pt::ptree txs;
    for (const auto& tx : template_block.transactions) {
        pt::ptree tx_json;
        tx_json.put("txid", tx.txid);
        tx_json.put("fee", tx.fee);
        
        txs.push_back(std::make_pair("", tx_json));
    }
    json.add_child("transactions", txs);
    
    // Add share table
    pt::ptree share_table;
    for (const auto& pair : template_block.share_table) {
        pt::ptree entry;
        entry.put("", pair.second);
        share_table.add_child(pair.first, entry);
    }
    json.add_child("share_table", share_table);
    
    // Convert to string
    std::stringstream ss;
    pt::write_json(ss, json);
    
    return ss.str();
}

void RPC::accept_connections() {
    if (!is_running_) {
        return;
    }
    
    acceptor_.async_accept(
        [this](const boost::system::error_code& error, boost::asio::ip::tcp::socket socket) {
            if (!error) {
                // Process the connection in a new session
                std::thread([this, s = std::move(socket)]() mutable {
                    try {
                        // Create buffer for reading
                        beast::flat_buffer buffer;
                        
                        // Create the HTTP request object
                        http::request<http::string_body> req;
                        
                        // Read the HTTP request
                        beast::error_code ec;
                        http::read(s, buffer, req, ec);
                        
                        if (ec) {
                            std::cerr << "Error reading request: " << ec.message() << std::endl;
                            return;
                        }
                        
                        // Create the HTTP response object
                        http::response<http::string_body> res;
                        res.version(req.version());
                        res.keep_alive(false);
                        
                        // Handle the request
                        handle_request(req, res);
                        
                        // Write the response
                        http::write(s, res, ec);
                        
                        if (ec) {
                            std::cerr << "Error writing response: " << ec.message() << std::endl;
                        }
                        
                        // Shutdown the socket
                        s.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                        if (ec && ec != boost::asio::error::not_connected) {
                            std::cerr << "Error shutting down socket: " << ec.message() << std::endl;
                        }
                        
                        // Close the socket
                        ec = boost::system::error_code();
                        s.close(ec);
                        if (ec) {
                            std::cerr << "Error closing socket: " << ec.message() << std::endl;
                        }
                    }
                    catch (const std::exception& e) {
                        std::cerr << "Exception in connection handler: " << e.what() << std::endl;
                    }
                }).detach();
            }
            else {
                std::cerr << "Accept error: " << error.message() << std::endl;
            }
            
            // Continue accepting connections
            if (is_running_) {
                accept_connections();
            }
        }
    );
}

std::string RPC::request_pocol_range(const std::string& params) {
    try {
        // Parse the params
        std::stringstream ss(params);
        pt::ptree json;
        pt::read_json(ss, json);
        
        // Get the public key (miner_id)
        std::string public_key = json.get<std::string>("public_key", miner_->get_miner_id());
        
        // Get the signature
        std::string signature = json.get<std::string>("signature", "");
        
        // Message that was signed (can be a timestamp or nonce to prevent replay attacks)
        std::string message = json.get<std::string>("message", "request_range");
        
        // Check if the miner is registered
        if (g_registered_miners.find(public_key) == g_registered_miners.end()) {
            pt::ptree result;
            result.put("success", false);
            result.put("error", "Miner not registered. Please register first.");
            
            std::stringstream result_ss;
            pt::write_json(result_ss, result);
            return result_ss.str();
        }
        
        // Verify the signature if provided
        if (!signature.empty() && !verify_signature(message, signature, public_key)) {
            pt::ptree result;
            result.put("success", false);
            result.put("error", "Invalid signature. Authentication failed.");
            
            std::stringstream result_ss;
            pt::write_json(result_ss, result);
            return result_ss.str();
        }
        
        // Set the miner ID (public key)
        miner_->set_miner_id(public_key);
        
        // Request a range
        bool success = miner_->request_range();
        
        // Return the result
        pt::ptree result;
        result.put("success", success);
        
        if (success) {
            // Get the current range
            Range range = miner_->current_range_;
            
            result.put("range_id", range.id);
            result.put("start", range.start);
            result.put("end", range.end);
            result.put("public_key", public_key);
        }
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        pt::ptree result;
        result.put("success", false);
        result.put("error", std::string("Error requesting range: ") + e.what());
        
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        return result_ss.str();
    }
}

std::string RPC::submit_pocol_share(const std::string& params) {
    try {
        // Parse the params
        std::stringstream ss(params);
        pt::ptree json;
        pt::read_json(ss, json);
        
        // Create a share
        Share share;
        share.header = json.get<std::string>("header");
        share.nonce = json.get<int>("nonce");
        share.proof = json.get<std::string>("proof", "");
        share.miner_id = json.get<std::string>("public_key", miner_->get_miner_id());
        
        // Get the signature
        std::string signature = json.get<std::string>("signature", "");
        
        // Message that was signed (can be the share data itself)
        std::string message = share.header + std::to_string(share.nonce);
        
        // Check if the miner is registered
        if (g_registered_miners.find(share.miner_id) == g_registered_miners.end()) {
            pt::ptree result;
            result.put("success", false);
            result.put("error", "Miner not registered. Please register first.");
            
            std::stringstream result_ss;
            pt::write_json(result_ss, result);
            return result_ss.str();
        }
        
        // Verify the signature if provided
        if (!signature.empty() && !verify_signature(message, signature, share.miner_id)) {
            pt::ptree result;
            result.put("success", false);
            result.put("error", "Invalid signature. Authentication failed.");
            
            std::stringstream result_ss;
            pt::write_json(result_ss, result);
            return result_ss.str();
        }
        
        // Submit the share
        bool success = share_manager_->add_share(share.miner_id, share);
        
        // Return the result
        pt::ptree result;
        result.put("success", success);
        
        if (success) {
            // Get the share count for this miner
            int32_t share_count = share_manager_->get_share_count(share.miner_id);
            result.put("share_count", share_count);
            
            // Update the share table in the current template
            Block current_template = template_builder_->get_current_template();
            current_template.share_table[share.miner_id] = share_count;
            
            // Check if the share meets the block target
            if (miner_->meets_block_target(share.proof)) {
                // Found a block!
                Block block = template_builder_->finalize_block(share.nonce);
                miner_->submit_block(block);
                
                result.put("found_block", true);
                result.put("block_hash", block.hash);
                
                // Calculate rewards
                std::unordered_map<std::string, double> rewards = share_manager_->calculate_rewards(100.0); // 100 coins per block
                
                // Create coinbase transactions for each miner
                for (const auto& reward_pair : rewards) {
                    std::string public_key = reward_pair.first;
                    double reward = reward_pair.second;
                    
                    // Create a coinbase transaction
                    Transaction tx;
                    tx.inputs.push_back("coinbase:0");
                    tx.outputs.push_back(public_key + ":" + std::to_string(static_cast<int64_t>(reward)));
                    tx.fee = 0;
                    tx.timestamp = std::time(nullptr);
                    
                    // Calculate the transaction ID
                    std::string tx_data;
                    for (const auto& input : tx.inputs) {
                        tx_data += input;
                    }
                    for (const auto& output : tx.outputs) {
                        tx_data += output;
                    }
                    tx_data += std::to_string(tx.fee);
                    tx_data += std::to_string(tx.timestamp);
                    
                    // Double SHA-256 hash
                    std::string hash = compute_double_sha256(tx_data);
                    
                    // Reverse byte order (Bitcoin uses little-endian)
                    std::string reversed_hash = reverse_bytes(hash);
                    
                    // Convert to hex string
                    tx.txid = bytes_to_hex_string(reversed_hash);
                    
                    // Add the transaction to the UTXO set
                    UTXOSet& utxo_set = get_utxo_set();
                    utxo_set.add_transaction(tx);
                    
                    // Store the transaction in our transaction history
                    store_transaction_history(tx);
                }
                
                // Clear the share manager for the next block
                share_manager_->clear();
            }
        }
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        pt::ptree result;
        result.put("success", false);
        result.put("error", std::string("Error submitting share: ") + e.what());
        
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        return result_ss.str();
    }
}

std::string RPC::register_pocol_miner(const std::string& params) {
    try {
        // Parse the params
        std::stringstream ss(params);
        pt::ptree json;
        pt::read_json(ss, json);
        
        // Get the public key
        std::string public_key = json.get<std::string>("public_key");
        
        // Get the signature
        std::string signature = json.get<std::string>("signature", "");
        
        // Message that was signed (can be a timestamp or nonce to prevent replay attacks)
        std::string message = json.get<std::string>("message", "register_miner");
        
        // Verify the signature if provided
        if (!signature.empty() && !verify_signature(message, signature, public_key)) {
            pt::ptree result;
            result.put("success", false);
            result.put("error", "Invalid signature. Authentication failed.");
            
            std::stringstream result_ss;
            pt::write_json(result_ss, result);
            return result_ss.str();
        }
        
        // Add the public key to our global set of addresses
        g_all_addresses.insert(public_key);
        
        // Register the miner
        g_registered_miners.insert(public_key);
        
        // Return the result
        pt::ptree result;
        result.put("success", true);
        result.put("public_key", public_key);
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        pt::ptree result;
        result.put("success", false);
        result.put("error", std::string("Error registering miner: ") + e.what());
        
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        return result_ss.str();
    }
}

std::string RPC::get_pocol_rewards(const std::string& params) {
    try {
        // Parse the params
        std::stringstream ss(params);
        pt::ptree json;
        pt::read_json(ss, json);
        
        // Get the public key
        std::string public_key = json.get<std::string>("public_key", "");
        
        // Calculate rewards
        std::unordered_map<std::string, double> rewards = share_manager_->calculate_rewards(100.0); // 100 coins per block
        
        // Return the result
        pt::ptree result;
        
        if (public_key.empty()) {
            // Return all rewards
            pt::ptree rewards_json;
            for (const auto& pair : rewards) {
                pt::ptree entry;
                entry.put("", pair.second);
                rewards_json.add_child(pair.first, entry);
            }
            result.add_child("rewards", rewards_json);
        } else {
            // Return rewards for a specific miner
            auto it = rewards.find(public_key);
            if (it != rewards.end()) {
                result.put("public_key", public_key);
                result.put("reward", it->second);
            } else {
                result.put("public_key", public_key);
                result.put("reward", 0.0);
            }
        }
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        pt::ptree result;
        result.put("success", false);
        result.put("error", std::string("Error getting rewards: ") + e.what());
        
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        return result_ss.str();
    }
}

std::string RPC::get_pocol_miners(const std::string& params) {
    try {
        // Return the list of registered miners
        pt::ptree result;
        
        pt::ptree miners_json;
        for (const auto& public_key : g_registered_miners) {
            pt::ptree entry;
            entry.put("", public_key);
            miners_json.push_back(std::make_pair("", entry));
        }
        result.add_child("miners", miners_json);
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        pt::ptree result;
        result.put("success", false);
        result.put("error", std::string("Error getting miners: ") + e.what());
        
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        return result_ss.str();
    }
}

std::string RPC::complete_pocol_range(const std::string& params) {
    try {
        // Parse the params
        std::stringstream ss(params);
        pt::ptree json;
        pt::read_json(ss, json);
        
        // Get the range ID and public key
        int32_t range_id = json.get<int32_t>("range_id");
        std::string public_key = json.get<std::string>("public_key", miner_->get_miner_id());
        
        // Get the signature
        std::string signature = json.get<std::string>("signature", "");
        
        // Message that was signed (can be the range ID)
        std::string message = std::to_string(range_id);
        
        // Check if the miner is registered
        if (g_registered_miners.find(public_key) == g_registered_miners.end()) {
            pt::ptree result;
            result.put("success", false);
            result.put("error", "Miner not registered. Please register first.");
            
            std::stringstream result_ss;
            pt::write_json(result_ss, result);
            return result_ss.str();
        }
        
        // Verify the signature if provided
        if (!signature.empty() && !verify_signature(message, signature, public_key)) {
            pt::ptree result;
            result.put("success", false);
            result.put("error", "Invalid signature. Authentication failed.");
            
            std::stringstream result_ss;
            pt::write_json(result_ss, result);
            return result_ss.str();
        }
        
        // Create a range complete notification
        RangeComplete complete;
        complete.range_id = range_id;
        complete.miner_id = public_key;
        
        // Handle the range complete notification
        miner_->handle_range_complete(complete);
        
        // Return the result
        pt::ptree result;
        result.put("success", true);
        result.put("range_id", range_id);
        result.put("public_key", public_key);
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        pt::ptree result;
        result.put("success", false);
        result.put("error", std::string("Error completing range: ") + e.what());
        
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        return result_ss.str();
    }
}

std::string RPC::get_pocol_balance(const std::string& params) {
    try {
        // Parse the params
        std::stringstream ss(params);
        pt::ptree json;
        pt::read_json(ss, json);
        
        // Get the address
        std::string address = json.get<std::string>("address");
        
        // Add the address to our global set
        g_all_addresses.insert(address);
        
        // Get the balance from the UTXO set
        int64_t balance = get_utxo_set().get_balance(address);
        
        // Return the result
        pt::ptree result;
        result.put("address", address);
        result.put("balance", balance);
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        throw std::runtime_error("Invalid params: " + std::string(e.what()));
    }
}

std::string RPC::create_pocol_transaction(const std::string& params) {
    try {
        // Parse the params
        std::stringstream ss(params);
        pt::ptree json;
        pt::read_json(ss, json);
        
        // Extract transaction details
        std::vector<std::string> inputs;
        std::vector<std::string> outputs;
        int64_t fee = 0;
        std::string private_key;
        
        // Parse inputs
        for (const auto& input : json.get_child("inputs")) {
            inputs.push_back(input.second.get_value<std::string>());
        }
        
        // Parse outputs
        for (const auto& output : json.get_child("outputs")) {
            std::string output_str = output.second.get_value<std::string>();
            outputs.push_back(output_str);
            
            // Extract the address from the output
            size_t colon_pos = output_str.find(':');
            if (colon_pos != std::string::npos) {
                std::string address = output_str.substr(0, colon_pos);
                g_all_addresses.insert(address);
            }
        }
        
        // Get fee and private key
        fee = json.get<int64_t>("fee", 0);
        private_key = json.get<std::string>("private_key", "");
        
        // Create the transaction
        Transaction tx = create_transaction(inputs, outputs, fee, private_key);
        
        // First, validate the transaction
        UTXOSet& utxo_set = get_utxo_set();
        if (!utxo_set.validate_transaction(tx)) {
            // Return error without modifying the UTXO set
            pt::ptree result;
            result.put("success", false);
            result.put("error", "Transaction validation failed");
            result.put("txid", tx.txid);
            
            std::stringstream result_ss;
            pt::write_json(result_ss, result);
            return result_ss.str();
        }
        
        // Transaction is valid, now spend the inputs
        if (!utxo_set.spend_outputs(tx)) {
            pt::ptree result;
            result.put("success", false);
            result.put("error", "Failed to spend transaction inputs");
            result.put("txid", tx.txid);
            
            std::stringstream result_ss;
            pt::write_json(result_ss, result);
            return result_ss.str();
        }
        
        // Add the outputs to the UTXO set
        if (!utxo_set.add_transaction(tx)) {
            // This is a serious error - we've spent the inputs but failed to add the outputs
            // In a real implementation, we would need to roll back the spent inputs
            pt::ptree result;
            result.put("success", false);
            result.put("error", "Failed to add transaction outputs to UTXO set");
            result.put("txid", tx.txid);
            
            std::stringstream result_ss;
            pt::write_json(result_ss, result);
            return result_ss.str();
        }
        
        // Add the transaction to the mempool
        bool added = template_builder_->get_mempool()->add_transaction(tx);
        
        // Store the transaction in our transaction history
        // This ensures we can look it up even if it's not in the mempool
        store_transaction_history(tx);
        
        // Return the result
        pt::ptree result;
        result.put("success", true);  // We consider it successful even if not added to mempool
        if (!added) {
            result.put("warning", "Transaction processed but not added to mempool");
        }
        result.put("txid", tx.txid);
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        pt::ptree result;
        result.put("success", false);
        result.put("error", std::string("Transaction error: ") + e.what());
        
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        return result_ss.str();
    }
}

std::string RPC::get_pocol_transaction(const std::string& params) {
    try {
        // Parse the params
        std::stringstream ss(params);
        pt::ptree json;
        pt::read_json(ss, json);
        
        // Get the transaction ID
        std::string txid = json.get<std::string>("txid");
        
        // First, try to get the transaction from the mempool
        Transaction tx = template_builder_->get_mempool()->get_transaction(txid);
        
        // If not found in mempool, try to get it from our transaction history
        if (tx.txid.empty()) {
            tx = get_transaction_history(txid);
        }
        
        // If still not found, try to reconstruct it from the UTXO set
        if (tx.txid.empty()) {
            // Get all UTXOs for this transaction
            UTXOSet& utxo_set = get_utxo_set();
            std::vector<TransactionOutput> utxos;
            
            // Scan all addresses to find UTXOs with this txid
            for (const auto& address : get_all_addresses()) {
                auto address_utxos = utxo_set.get_utxos_for_address(address);
                for (const auto& utxo : address_utxos) {
                    if (utxo.txid == txid) {
                        utxos.push_back(utxo);
                    }
                }
            }
            
            // If we found UTXOs, reconstruct the transaction
            if (!utxos.empty()) {
                tx.txid = txid;
                
                // For coinbase transactions
                if (utxos.size() == 1 && utxos[0].index == 0) {
                    tx.inputs.push_back("coinbase:0");
                }
                
                // Add outputs
                for (const auto& utxo : utxos) {
                    tx.outputs.push_back(utxo.address + ":" + std::to_string(utxo.amount));
                }
                
                // Set fee and timestamp (approximate)
                tx.fee = 0; // We don't know the actual fee
                tx.timestamp = std::time(nullptr) - 3600; // Approximate timestamp (1 hour ago)
            }
        }
        
        // Check if the transaction exists
        if (tx.txid.empty()) {
            throw std::runtime_error("Transaction not found");
        }
        
        // Convert the transaction to JSON
        pt::ptree tx_json;
        tx_json.put("txid", tx.txid);
        
        // Add inputs
        pt::ptree inputs;
        for (const auto& input : tx.inputs) {
            pt::ptree input_json;
            input_json.put("", input);
            inputs.push_back(std::make_pair("", input_json));
        }
        tx_json.add_child("inputs", inputs);
        
        // Add outputs
        pt::ptree outputs;
        for (const auto& output : tx.outputs) {
            pt::ptree output_json;
            output_json.put("", output);
            outputs.push_back(std::make_pair("", output_json));
        }
        tx_json.add_child("outputs", outputs);
        
        tx_json.put("fee", tx.fee);
        tx_json.put("timestamp", tx.timestamp);
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, tx_json);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        throw std::runtime_error("Invalid params: " + std::string(e.what()));
    }
}

std::string RPC::get_pocol_utxos(const std::string& params) {
    try {
        // Parse the params
        std::stringstream ss(params);
        pt::ptree json;
        pt::read_json(ss, json);
        
        // Get the address
        std::string address = json.get<std::string>("address");
        
        // Add the address to our global set
        g_all_addresses.insert(address);
        
        // Get the UTXOs for the address
        std::vector<TransactionOutput> utxos = get_utxo_set().get_utxos_for_address(address);
        
        // Convert the UTXOs to JSON
        pt::ptree result;
        result.put("address", address);
        
        pt::ptree utxos_json;
        for (const auto& utxo : utxos) {
            pt::ptree utxo_json;
            utxo_json.put("txid", utxo.txid);
            utxo_json.put("index", utxo.index);
            utxo_json.put("amount", utxo.amount);
            
            utxos_json.push_back(std::make_pair("", utxo_json));
        }
        
        // If there are no UTXOs, add an empty array to avoid null
        if (utxos.empty()) {
            result.add_child("utxos", utxos_json);
            result.put("message", "No UTXOs found for this address");
        } else {
            result.add_child("utxos", utxos_json);
        }
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        // Create a proper error response instead of throwing
        pt::ptree error_json;
        error_json.put("error", std::string("Error processing request: ") + e.what());
        error_json.put("status", "error");
        
        std::stringstream error_ss;
        pt::write_json(error_ss, error_json);
        return error_ss.str();
    }
}

std::string RPC::get_pocol_utxo(const std::string& params) {
    try {
        // Parse the params
        std::stringstream ss(params);
        pt::ptree json;
        pt::read_json(ss, json);
        
        // Get the transaction ID and output index
        std::string txid = json.get<std::string>("txid");
        uint32_t index = json.get<uint32_t>("index");
        
        // Get the UTXO
        TransactionOutput utxo = get_utxo_set().get_utxo(txid, index);
        
        // Check if the UTXO exists
        if (utxo.txid.empty()) {
            throw std::runtime_error("UTXO not found");
        }
        
        // Add the address to our global set
        g_all_addresses.insert(utxo.address);
        
        // Convert the UTXO to JSON
        pt::ptree result;
        result.put("txid", utxo.txid);
        result.put("index", utxo.index);
        result.put("address", utxo.address);
        result.put("amount", utxo.amount);
        result.put("is_spent", utxo.is_spent);
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        throw std::runtime_error("Invalid params: " + std::string(e.what()));
    }
}

std::string RPC::create_coinbase_transaction(const std::string& params) {
    try {
        // Parse the params
        std::stringstream ss(params);
        pt::ptree json;
        pt::read_json(ss, json);
        
        // Get the address to receive the coinbase
        std::string address = json.get<std::string>("address");
        
        // Add the address to our global set
        g_all_addresses.insert(address);
        
        // Create a coinbase transaction
        Transaction tx;
        
        // Set transaction data
        tx.inputs.push_back("coinbase:0"); // Special input for coinbase
        tx.outputs.push_back(address + ":100"); // 100 coins to the specified address
        tx.fee = 0; // No fee for coinbase
        tx.timestamp = std::time(nullptr);
        
        // Calculate the transaction ID in Bitcoin style
        std::string tx_data;
        for (const auto& input : tx.inputs) {
            tx_data += input;
        }
        for (const auto& output : tx.outputs) {
            tx_data += output;
        }
        tx_data += std::to_string(tx.fee);
        tx_data += std::to_string(tx.timestamp);
        
        // Double SHA-256 hash
        std::string hash = compute_double_sha256(tx_data);
        
        // Reverse byte order (Bitcoin uses little-endian)
        std::string reversed_hash = reverse_bytes(hash);
        
        // Convert to hex string
        tx.txid = bytes_to_hex_string(reversed_hash);
        
        // Add the transaction to the UTXO set directly
        UTXOSet& utxo_set = get_utxo_set();
        bool added = utxo_set.add_transaction(tx);
        
        // Also add to mempool for inclusion in next block
        template_builder_->get_mempool()->add_transaction(tx);
        
        // Store the transaction in our transaction history
        store_transaction_history(tx);
        
        // Return the result
        pt::ptree result;
        result.put("success", added);
        result.put("txid", tx.txid);
        result.put("output_index", 0);  // Explicitly show the output index
        result.put("amount", 100);
        result.put("address", address);
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        throw std::runtime_error("Invalid params: " + std::string(e.what()));
    }
}

// Helper method to get all addresses with UTXOs
std::vector<std::string> RPC::get_all_addresses() {
    std::vector<std::string> addresses;
    
    // Return all addresses we've seen
    for (const auto& address : g_all_addresses) {
        addresses.push_back(address);
    }
    
    return addresses;
}

void RPC::store_transaction_history(const Transaction& tx) {
    g_transaction_history[tx.txid] = tx;
}

Transaction RPC::get_transaction_history(const std::string& txid) {
    auto it = g_transaction_history.find(txid);
    if (it != g_transaction_history.end()) {
        return it->second;
    }
    return Transaction(); // Empty transaction if not found
}

} // namespace pocol
