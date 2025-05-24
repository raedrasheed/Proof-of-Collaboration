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
#include <chrono>
#include <atomic>

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
    
    std::cout << "DEBUG: RPC constructor called with port " << port << std::endl;
    std::cout << "DEBUG: template_builder_ = " << template_builder_.get() << std::endl;
    std::cout << "DEBUG: miner_ = " << miner_.get() << std::endl;
    std::cout << "DEBUG: share_manager_ = " << share_manager_.get() << std::endl;
    
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
    
    rpc_methods_["listutxos"] = [this](const std::string& params) {
        return list_all_utxos(params);
    };

    rpc_methods_["gettransactionoutputs"] = [this](const std::string& params) {
        return get_transaction_outputs(params);
    };

    rpc_methods_["getmempool"] = [this](const std::string& params) {
        return get_mempool(params);
    };

    rpc_methods_["getmempoolinfo"] = [this](const std::string& params) {
        return get_mempool_info(params);
    };
    
    // Initialize with some default addresses
    g_all_addresses.insert("e707f705f7cabd3a00e12eca0b96f66be707f705f7cabd3a00e12eca0b96f66be707f705f7cabd3a00e12eca0b96f66be707f705f7cabd3a00e12eca0b96f66b");
    g_all_addresses.insert("bcc4a36d6821c0988ee68f600581c310bcc4a36d6821c0988ee68f600581c310bcc4a36d6821c0988ee68f600581c310bcc4a36d6821c0988ee68f600581c310");
    
    // Register a default miner (using public key as miner_id)
    g_registered_miners.insert("e707f705f7cabd3a00e12eca0b96f66be707f705f7cabd3a00e12eca0b96f66be707f705f7cabd3a00e12eca0b96f66be707f705f7cabd3a00e12eca0b96f66b");
    
    // Initialize the template builder with a genesis block
    std::cout << "DEBUG: Initializing template builder with genesis block" << std::endl;
    try {
        std::string genesis_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        template_builder_->build_template(genesis_hash);
        std::cout << "DEBUG: Template builder initialized successfully" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: Failed to initialize template builder: " << e.what() << std::endl;
    }
}

RPC::~RPC() {
    std::cout << "DEBUG: RPC destructor called" << std::endl;
    stop();
}

void RPC::start() {
    std::cout << "DEBUG: RPC::start() called" << std::endl;
    
    if (is_running_) {
        std::cout << "DEBUG: RPC already running, ignoring start request" << std::endl;
        return;
    }
    
    is_running_ = true;
    
    // Start accepting connections
    std::cout << "DEBUG: Starting to accept connections" << std::endl;
    accept_connections();
    
    // Start the io_context in a separate thread
    std::cout << "DEBUG: Starting io_context thread" << std::endl;
    std::thread([this]() {
        try {
            std::cout << "DEBUG: io_context thread started" << std::endl;
            io_context_.run();
            std::cout << "DEBUG: io_context thread finished" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "ERROR: Exception in io_context thread: " << e.what() << std::endl;
        }
    }).detach();
    
    std::cout << "DEBUG: RPC::start() completed" << std::endl;
}

void RPC::stop() {
    std::cout << "DEBUG: RPC::stop() called" << std::endl;
    
    if (!is_running_) {
        std::cout << "DEBUG: RPC not running, ignoring stop request" << std::endl;
        return;
    }
    
    is_running_ = false;
    
    // Stop accepting connections
    std::cout << "DEBUG: Stopping acceptor" << std::endl;
    beast::error_code ec;
    acceptor_.close(ec);
    if (ec) {
        std::cerr << "ERROR: Failed to close acceptor: " << ec.message() << std::endl;
    }
    
    // Stop the io_context
    std::cout << "DEBUG: Stopping io_context" << std::endl;
    io_context_.stop();
    
    std::cout << "DEBUG: RPC::stop() completed" << std::endl;
}

void RPC::handle_request(http::request<http::string_body>& req, http::response<http::string_body>& res) {
    std::cout << "DEBUG: RPC::handle_request() called" << std::endl;
    std::cout << "DEBUG: Request method: " << req.method_string() << std::endl;
    std::cout << "DEBUG: Request target: " << req.target() << std::endl;
    std::cout << "DEBUG: Request body: " << req.body() << std::endl;
    
    // Set the response headers
    res.set(http::field::server, "pocol-rpc");
    res.set(http::field::content_type, "application/json");
    res.set(http::field::access_control_allow_origin, "*");  // Allow CORS
    
    try {
        // Parse the JSON-RPC request
        std::string method;
        std::string params;
        int id;
        
        std::cout << "DEBUG: Parsing JSON-RPC request" << std::endl;
        if (!parse_json_rpc(req.body(), method, params, id)) {
            // Invalid JSON-RPC request
            std::cout << "DEBUG: Invalid JSON-RPC request" << std::endl;
            res.result(http::status::bad_request);
            res.body() = R"({"error": "Invalid JSON-RPC request", "id": null})";
            return;
        }
        
        std::cout << "DEBUG: JSON-RPC method: " << method << std::endl;
        std::cout << "DEBUG: JSON-RPC params: " << params << std::endl;
        std::cout << "DEBUG: JSON-RPC id: " << id << std::endl;
        
        // Find the RPC method
        auto it = rpc_methods_.find(method);
        if (it == rpc_methods_.end()) {
            // Method not found
            std::cout << "DEBUG: Method not found: " << method << std::endl;
            res.result(http::status::not_found);
            res.body() = R"({"error": "Method not found", "id": )" + std::to_string(id) + "}";
            return;
        }
        
        // Call the RPC method
        try {
            std::cout << "DEBUG: Calling RPC method: " << method << std::endl;
            auto start_time = std::chrono::high_resolution_clock::now();
            
            std::string result = it->second(params);
            
            auto end_time = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
            std::cout << "DEBUG: RPC method " << method << " completed in " << duration << " ms" << std::endl;
            
            res.result(http::status::ok);
            
            // Check if the result is already a JSON object
            if (result.empty() || result[0] != '{') {
                std::cout << "DEBUG: Wrapping result in JSON object" << std::endl;
                res.body() = R"({"result": )" + result + R"(, "id": )" + std::to_string(id) + "}";
            } else {
                // Result is already a JSON object, just wrap it with id
                std::cout << "DEBUG: Result is already a JSON object" << std::endl;
                res.body() = result;
            }
            
            std::cout << "DEBUG: Response body: " << res.body() << std::endl;
        } catch (const std::exception& e) {
            // Error executing the method
            std::cerr << "ERROR: Exception in RPC method " << method << ": " << e.what() << std::endl;
            res.result(http::status::internal_server_error);
            res.body() = R"({"error": ")" + std::string(e.what()) + R"(", "id": )" + std::to_string(id) + "}";
        }
    } catch (const std::exception& e) {
        // Unexpected error
        std::cerr << "ERROR: Unexpected exception in handle_request: " << e.what() << std::endl;
        res.result(http::status::internal_server_error);
        res.body() = R"({"error": "Internal server error", "id": null})";
    }
    
    std::cout << "DEBUG: RPC::handle_request() completed" << std::endl;
}

bool RPC::parse_json_rpc(const std::string& body, std::string& method, std::string& params, int& id) {
    std::cout << "DEBUG: RPC::parse_json_rpc() called" << std::endl;
    
    try {
        // Parse the JSON
        std::stringstream ss(body);
        pt::ptree json;
        pt::read_json(ss, json);
        
        // Check if it's a valid JSON-RPC request
        std::string jsonrpc = json.get<std::string>("jsonrpc", "");
        if (jsonrpc != "2.0") {
            std::cout << "DEBUG: Invalid jsonrpc version: " << jsonrpc << std::endl;
            return false;
        }
        
        // Get the method
        method = json.get<std::string>("method");
        std::cout << "DEBUG: Parsed method: " << method << std::endl;
        
        // Get the params
        try {
            // First try to get params as a string
            params = json.get<std::string>("params", "");
            std::cout << "DEBUG: Parsed params as string: " << params << std::endl;
        } catch (const pt::ptree_bad_data&) {
            // If that fails, try to get it as a JSON object
            std::cout << "DEBUG: Params is not a string, trying to parse as JSON object" << std::endl;
            pt::ptree params_json = json.get_child("params");
            std::stringstream params_ss;
            pt::write_json(params_ss, params_json);
            params = params_ss.str();
            std::cout << "DEBUG: Parsed params as JSON object: " << params << std::endl;
        }
        
        // Get the id
        id = json.get<int>("id");
        std::cout << "DEBUG: Parsed id: " << id << std::endl;
        
        std::cout << "DEBUG: RPC::parse_json_rpc() completed successfully" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: Exception in parse_json_rpc: " << e.what() << std::endl;
        return false;
    }
}

std::string RPC::get_pocol_template() {
    std::cout << "DEBUG: RPC::get_pocol_template() called" << std::endl;
    
    try {
        // Record start time
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Set up a timeout mechanism using a flag instead of a thread
        std::atomic<bool> timeout_occurred(false);
        
        // We'll check for timeout manually instead of using a separate thread
        auto check_timeout = [&start_time, &timeout_occurred]() {
            auto current_time = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();
            if (elapsed >= 5) {
                std::cerr << "ERROR: get_pocol_template is taking too long (5+ seconds), possible deadlock" << std::endl;
                timeout_occurred = true;
                return true;
            }
            return false;
        };
        
        // Check if template_builder_ is valid
        if (!template_builder_) {
            std::cerr << "ERROR: template_builder_ is null" << std::endl;
            throw std::runtime_error("Template builder is not initialized");
        }
        
        std::cout << "DEBUG: template_builder_ address: " << template_builder_.get() << std::endl;
        
        // Create a timeout for the mutex lock
        std::cout << "DEBUG: Creating a timeout for getting the template" << std::endl;
        auto timeout = std::chrono::system_clock::now() + std::chrono::seconds(3);
        
        // Get the current template with a timeout
        std::cout << "DEBUG: About to get current template with timeout" << std::endl;
        Block template_block;
        
        try {
            // Create a copy of the template to avoid holding the lock for too long
            std::cout << "DEBUG: About to call get_current_template()" << std::endl;
            template_block = template_builder_->get_current_template();
            std::cout << "DEBUG: Successfully returned from get_current_template()" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "ERROR: Exception getting current template: " << e.what() << std::endl;
            throw;
        }
        
        // Check if a timeout occurred
        if (timeout_occurred) {
            std::cerr << "ERROR: Timeout occurred while getting template" << std::endl;
            throw std::runtime_error("Timeout occurred while getting template");
        }
        
        // Add more debug output
        std::cout << "DEBUG: template prev_hash: " << template_block.prev_hash << std::endl;
        std::cout << "DEBUG: template merkle_root: " << template_block.merkle_root << std::endl;
        std::cout << "DEBUG: template timestamp: " << template_block.timestamp << std::endl;
        std::cout << "DEBUG: template transactions count: " << template_block.transactions.size() << std::endl;
        
        // Convert the template to JSON
        std::cout << "DEBUG: Converting template to JSON" << std::endl;
        pt::ptree json;
        
        // Convert binary hashes to hex strings for readability
        json.put("prev_hash", bytes_to_hex_string(template_block.prev_hash));
        json.put("merkle_root", bytes_to_hex_string(template_block.merkle_root));
        json.put("timestamp", template_block.timestamp);
        
        // Add transactions
        std::cout << "DEBUG: Adding transactions to JSON" << std::endl;
        pt::ptree txs;
        for (const auto& tx : template_block.transactions) {
            pt::ptree tx_json;
            tx_json.put("txid", tx.txid);
            tx_json.put("fee", tx.fee);
            
            txs.push_back(std::make_pair("", tx_json));
        }
        json.add_child("transactions", txs);
        
        // Add share table
        std::cout << "DEBUG: Adding share table to JSON" << std::endl;
        pt::ptree share_table;
        for (const auto& pair : template_block.share_table) {
            pt::ptree entry;
            entry.put("", pair.second);
            share_table.add_child(pair.first, entry);
        }
        json.add_child("share_table", share_table);
        
        // Convert to string
        std::cout << "DEBUG: Converting JSON to string" << std::endl;
        std::stringstream ss;
        pt::write_json(ss, json);
        
        std::string result = ss.str();
        std::cout << "DEBUG: get_pocol_template response: " << result << std::endl;
        
        // Record end time and calculate duration
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        std::cout << "DEBUG: get_pocol_template completed in " << duration << " ms" << std::endl;
        
        return result;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: Exception in get_pocol_template: " << e.what() << std::endl;
        
        // Return an error response in JSON format
        pt::ptree error_json;
        error_json.put("error", std::string("Error getting template: ") + e.what());
        error_json.put("status", "error");
        
        std::stringstream error_ss;
        pt::write_json(error_ss, error_json);
        return error_ss.str();
    }
}

void RPC::accept_connections() {
    std::cout << "DEBUG: RPC::accept_connections() called" << std::endl;
    
    if (!is_running_) {
        std::cout << "DEBUG: RPC not running, ignoring accept_connections request" << std::endl;
        return;
    }
    
    acceptor_.async_accept(
        [this](const boost::system::error_code& error, boost::asio::ip::tcp::socket socket) {
            if (!error) {
                std::cout << "DEBUG: Accepted new connection from " 
                          << socket.remote_endpoint().address().to_string() 
                          << ":" << socket.remote_endpoint().port() << std::endl;
                
                // Process the connection in a new session
                std::thread([this, s = std::move(socket)]() mutable {
                    try {
                        std::cout << "DEBUG: Starting new connection handler thread" << std::endl;
                        
                        // Create buffer for reading
                        beast::flat_buffer buffer;
                        
                        // Create the HTTP request object
                        http::request<http::string_body> req;
                        
                        // Read the HTTP request
                        beast::error_code ec;
                        std::cout << "DEBUG: Reading HTTP request" << std::endl;
                        http::read(s, buffer, req, ec);
                        
                        if (ec) {
                            std::cerr << "ERROR: Error reading request: " << ec.message() << std::endl;
                            return;
                        }
                        
                        std::cout << "DEBUG: Read HTTP request successfully" << std::endl;
                        
                        // Create the HTTP response object
                        http::response<http::string_body> res;
                        res.version(req.version());
                        res.keep_alive(false);
                        
                        // Handle the request
                        std::cout << "DEBUG: Handling request" << std::endl;
                        handle_request(req, res);
                        
                        // Write the response
                        std::cout << "DEBUG: Writing response" << std::endl;
                        http::write(s, res, ec);
                        
                        if (ec) {
                            std::cerr << "ERROR: Error writing response: " << ec.message() << std::endl;
                        }
                        
                        // Shutdown the socket
                        std::cout << "DEBUG: Shutting down socket" << std::endl;
                        s.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                        if (ec && ec != boost::asio::error::not_connected) {
                            std::cerr << "ERROR: Error shutting down socket: " << ec.message() << std::endl;
                        }
                        
                        // Close the socket
                        std::cout << "DEBUG: Closing socket" << std::endl;
                        ec = boost::system::error_code();
                        s.close(ec);
                        if (ec) {
                            std::cerr << "ERROR: Error closing socket: " << ec.message() << std::endl;
                        }
                        
                        std::cout << "DEBUG: Connection handler thread completed" << std::endl;
                    }
                    catch (const std::exception& e) {
                        std::cerr << "ERROR: Exception in connection handler: " << e.what() << std::endl;
                    }
                }).detach();
            }
            else {
                std::cerr << "ERROR: Accept error: " << error.message() << std::endl;
            }
            
            // Continue accepting connections
            if (is_running_) {
                std::cout << "DEBUG: Continuing to accept connections" << std::endl;
                accept_connections();
            }
        }
    );
    
    std::cout << "DEBUG: RPC::accept_connections() completed" << std::endl;
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

std::string RPC::list_all_utxos(const std::string& params) {
    try {
        // Get all addresses
        std::vector<std::string> addresses = get_all_addresses();
        
        // Create the result JSON
        pt::ptree result;
        pt::ptree utxos_array;
        
        UTXOSet& utxo_set = get_utxo_set();
        
        for (const auto& address : addresses) {
            std::vector<TransactionOutput> utxos = utxo_set.get_utxos_for_address(address);
            
            for (const auto& utxo : utxos) {
                pt::ptree utxo_json;
                utxo_json.put("txid", utxo.txid);
                utxo_json.put("index", utxo.index);
                utxo_json.put("address", utxo.address);
                utxo_json.put("amount", utxo.amount);
                utxo_json.put("is_spent", utxo.is_spent);
                
                utxos_array.push_back(std::make_pair("", utxo_json));
            }
        }
        
        result.add_child("utxos", utxos_array);
        result.put("total_utxos", utxos_array.size());
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        pt::ptree error_json;
        error_json.put("error", std::string("Error listing UTXOs: ") + e.what());
        error_json.put("status", "error");
        
        std::stringstream error_ss;
        pt::write_json(error_ss, error_json);
        return error_ss.str();
    }
}

std::string RPC::get_transaction_outputs(const std::string& params) {
    try {
        // Parse the params
        std::stringstream ss(params);
        pt::ptree json;
        pt::read_json(ss, json);
        
        // Get the transaction ID
        std::string txid = json.get<std::string>("txid");
        
        // Get all addresses to search for outputs
        std::vector<std::string> addresses = get_all_addresses();
        
        // Find all outputs for this transaction
        std::vector<TransactionOutput> outputs;
        UTXOSet& utxo_set = get_utxo_set();
        
        for (const auto& address : addresses) {
            std::vector<TransactionOutput> address_utxos = utxo_set.get_utxos_for_address(address);
            for (const auto& utxo : address_utxos) {
                if (utxo.txid == txid) {
                    outputs.push_back(utxo);
                }
            }
        }
        
        // Sort outputs by index
        std::sort(outputs.begin(), outputs.end(), 
                  [](const TransactionOutput& a, const TransactionOutput& b) {
                      return a.index < b.index;
                  });
        
        // Create the result JSON
        pt::ptree result;
        result.put("txid", txid);
        
        pt::ptree outputs_array;
        for (const auto& output : outputs) {
            pt::ptree output_json;
            output_json.put("index", output.index);
            output_json.put("address", output.address);
            output_json.put("amount", output.amount);
            output_json.put("is_spent", output.is_spent);
            
            outputs_array.push_back(std::make_pair("", output_json));
        }
        
        result.add_child("outputs", outputs_array);
        result.put("total_outputs", outputs.size());
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        pt::ptree error_json;
        error_json.put("error", std::string("Error getting transaction outputs: ") + e.what());
        error_json.put("status", "error");
        
        std::stringstream error_ss;
        pt::write_json(error_ss, error_json);
        return error_ss.str();
    }
}

std::string RPC::get_mempool(const std::string& params) {
    try {
        // Get the mempool from the template builder
        auto mempool = template_builder_->get_mempool();
        
        // Get all transactions sorted by fee rate (using empty seed for now)
        std::vector<Transaction> transactions = mempool->get_sorted_transactions("");
        
        // Create the result JSON
        pt::ptree result;
        pt::ptree txs_array;
        
        for (const auto& tx : transactions) {
            pt::ptree tx_json;
            tx_json.put("txid", tx.txid);
            tx_json.put("fee", tx.fee);
            tx_json.put("timestamp", tx.timestamp);
            
            // Add inputs
            pt::ptree inputs_array;
            for (const auto& input : tx.inputs) {
                pt::ptree input_json;
                input_json.put("", input);
                inputs_array.push_back(std::make_pair("", input_json));
            }
            tx_json.add_child("inputs", inputs_array);
            
            // Add outputs
            pt::ptree outputs_array;
            for (const auto& output : tx.outputs) {
                pt::ptree output_json;
                output_json.put("", output);
                outputs_array.push_back(std::make_pair("", output_json));
            }
            tx_json.add_child("outputs", outputs_array);
            
            txs_array.push_back(std::make_pair("", tx_json));
        }
        
        result.add_child("transactions", txs_array);
        result.put("total_transactions", transactions.size());
        result.put("mempool_size", mempool->size());
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        pt::ptree error_json;
        error_json.put("error", std::string("Error getting mempool: ") + e.what());
        error_json.put("status", "error");
        
        std::stringstream error_ss;
        pt::write_json(error_ss, error_json);
        return error_ss.str();
    }
}

std::string RPC::get_mempool_info(const std::string& params) {
    try {
        // Get the mempool from the template builder
        auto mempool = template_builder_->get_mempool();
        
        // Get basic mempool statistics
        size_t mempool_size = mempool->size();
        
        // Get all transactions to calculate total fees
        std::vector<Transaction> transactions = mempool->get_sorted_transactions("");
        
        int64_t total_fees = 0;
        int64_t total_size = 0;
        
        for (const auto& tx : transactions) {
            total_fees += tx.fee;
            // Estimate transaction size (simplified)
            total_size += tx.txid.size() + tx.inputs.size() * 32 + tx.outputs.size() * 32;
        }
        
        // Create the result JSON
        pt::ptree result;
        result.put("size", mempool_size);
        result.put("total_fees", total_fees);
        result.put("estimated_size_bytes", total_size);
        
        if (mempool_size > 0) {
            result.put("average_fee", static_cast<double>(total_fees) / mempool_size);
            result.put("average_size_bytes", total_size / mempool_size);
        } else {
            result.put("average_fee", 0.0);
            result.put("average_size_bytes", 0);
        }
        
        // Convert to string
        std::stringstream result_ss;
        pt::write_json(result_ss, result);
        
        return result_ss.str();
    } catch (const std::exception& e) {
        pt::ptree error_json;
        error_json.put("error", std::string("Error getting mempool info: ") + e.what());
        error_json.put("status", "error");
        
        std::stringstream error_ss;
        pt::write_json(error_ss, error_json);
        return error_ss.str();
    }
}

} // namespace pocol
