#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "../include/crypto_utils.hpp"

namespace http = boost::beast::http;
namespace pt = boost::property_tree;

// Function to send JSON-RPC request
std::string send_rpc_request(const std::string& host, uint16_t port, 
                            const std::string& method, const std::string& params) {
    try {
        // Set up connection
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::resolver resolver(io_context);
        boost::asio::ip::tcp::socket socket(io_context);
        
        auto const results = resolver.resolve(host, std::to_string(port));
        boost::asio::connect(socket, results.begin(), results.end());
        
        // Prepare JSON-RPC request
        pt::ptree request;
        request.put("jsonrpc", "2.0");
        request.put("method", method);
        request.put("params", params);
        request.put("id", 1);
        
        std::ostringstream request_stream;
        pt::write_json(request_stream, request);
        std::string request_body = request_stream.str();
        
        // Prepare HTTP request
        http::request<http::string_body> req{http::verb::post, "/", 11};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, "pocol-cli");
        req.set(http::field::content_type, "application/json");
        req.set(http::field::content_length, std::to_string(request_body.size()));
        req.body() = request_body;
        
        // Send request
        http::write(socket, req);
        
        // Receive response
        boost::beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(socket, buffer, res);
        
        // Close connection
        socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
        
        return res.body();
    } catch (const std::exception& e) {
        return std::string("Error: ") + e.what();
    }
}

void print_help() {
    std::cout << "PoCol CLI Usage:" << std::endl;
    std::cout << "  getpocoltemplate                  - Get current block template" << std::endl;
    std::cout << "  registerpocolminer <public_key> <signature> - Register as a miner" << std::endl;
    std::cout << "  requestpocolrange <public_key> <signature> - Request a nonce range to mine" << std::endl;
    std::cout << "  submitpocolshare <header> <nonce> <public_key> <signature> - Submit a share" << std::endl;
    std::cout << "  completepocolrange <range_id> <public_key> <signature> - Mark a range as completed" << std::endl;
    std::cout << "  getpocolminers                    - Get list of registered miners" << std::endl;
    std::cout << "  getpocolrewards <public_key>      - Get rewards for a miner" << std::endl;
    std::cout << "  getpocolbalance <address>         - Get address balance" << std::endl;
    std::cout << "  createpocoltransaction            - Create and submit a new transaction" << std::endl;
    std::cout << "  getpocoltransaction <txid>        - Get transaction details" << std::endl;
    std::cout << "  getpocolutxos <address>           - Get UTXOs for an address" << std::endl;
    std::cout << "  getpocolutxo <txid> <index>       - Get a specific UTXO" << std::endl;
    std::cout << "  generatekeypair                   - Generate a new key pair for transactions" << std::endl;
    std::cout << "  createcoinbase <address>          - Create a coinbase transaction (for testing)" << std::endl;
    std::cout << "  mineblock <public_key>            - Mine a new block with transactions from the mempool" << std::endl;
    std::cout << "  help                              - Show this help message" << std::endl;
    std::cout << "  exit                              - Exit the CLI" << std::endl;
}

// Function to sign a message with a private key
std::string sign_message(const std::string& message, const std::string& private_key) {
    // In a real implementation, this would use proper cryptographic signing
    // For our simplified implementation, we'll just concatenate the message and private key and hash it
    return pocol::compute_sha256(message + private_key);
}

int main(int argc, char* argv[]) {
    std::string host = "localhost";
    uint16_t port = 8332;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--host" && i + 1 < argc) {
            host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        }
    }
    
    std::cout << "PoCol CLI" << std::endl;
    std::cout << "Connected to " << host << ":" << port << std::endl;
    std::cout << "Type 'help' for available commands" << std::endl;
    
    // Store the current key pair for convenience
    std::string current_private_key = "";
    std::string current_public_key = "";
    
    // Interactive CLI loop
    std::string line;
    while (true) {
        std::cout << "> ";
        std::getline(std::cin, line);
        
        if (line == "exit") {
            break;
        } else if (line == "help") {
            print_help();
            continue;
        }
        
        // Parse command
        std::istringstream iss(line);
        std::vector<std::string> tokens;
        std::string token;
        while (iss >> token) {
            tokens.push_back(token);
        }
        
        if (tokens.empty()) {
            continue;
        }
        
        std::string method = tokens[0];
        std::string params;
        
        if (method == "getpocoltemplate") {
            params = "";
        } else if (method == "registerpocolminer") {
            std::string public_key;
            std::string private_key;
            
            if (tokens.size() >= 2) {
                public_key = tokens[1];
            } else if (!current_public_key.empty()) {
                public_key = current_public_key;
            } else {
                std::cout << "Enter public key: ";
                std::getline(std::cin, public_key);
            }
            
            if (tokens.size() >= 3) {
                private_key = tokens[2];
            } else if (!current_private_key.empty()) {
                private_key = current_private_key;
            } else {
                std::cout << "Enter private key: ";
                std::getline(std::cin, private_key);
            }
            
            // Message to sign
            std::string message = "register_miner";
            
            // Sign the message
            std::string signature = sign_message(message, private_key);
            
            pt::ptree miner_params;
            miner_params.put("public_key", public_key);
            miner_params.put("signature", signature);
            miner_params.put("message", message);
            
            std::ostringstream params_stream;
            pt::write_json(params_stream, miner_params);
            params = params_stream.str();
        } else if (method == "requestpocolrange") {
            std::string public_key;
            std::string private_key;
            
            if (tokens.size() >= 2) {
                public_key = tokens[1];
            } else if (!current_public_key.empty()) {
                public_key = current_public_key;
            } else {
                std::cout << "Enter public key: ";
                std::getline(std::cin, public_key);
            }
            
            if (tokens.size() >= 3) {
                private_key = tokens[2];
            } else if (!current_private_key.empty()) {
                private_key = current_private_key;
            } else {
                std::cout << "Enter private key: ";
                std::getline(std::cin, private_key);
            }
            
            // Message to sign
            std::string message = "request_range";
            
            // Sign the message
            std::string signature = sign_message(message, private_key);
            
            pt::ptree range_params;
            range_params.put("public_key", public_key);
            range_params.put("signature", signature);
            range_params.put("message", message);
            
            std::ostringstream params_stream;
            pt::write_json(params_stream, range_params);
            params = params_stream.str();
        } else if (method == "submitpocolshare" && tokens.size() >= 3) {
            std::string header = tokens[1];
            int nonce = std::stoi(tokens[2]);
            std::string public_key;
            std::string private_key;
            
            if (tokens.size() >= 4) {
                public_key = tokens[3];
            } else if (!current_public_key.empty()) {
                public_key = current_public_key;
            } else {
                std::cout << "Enter public key: ";
                std::getline(std::cin, public_key);
            }
            
            if (tokens.size() >= 5) {
                private_key = tokens[4];
            } else if (!current_private_key.empty()) {
                private_key = current_private_key;
            } else {
                std::cout << "Enter private key: ";
                std::getline(std::cin, private_key);
            }
            
            // Message to sign (the share data itself)
            std::string message = header + std::to_string(nonce);
            
            // Sign the message
            std::string signature = sign_message(message, private_key);
            
            pt::ptree share_params;
            share_params.put("header", header);
            share_params.put("nonce", nonce);
            share_params.put("public_key", public_key);
            share_params.put("signature", signature);
            
            std::ostringstream params_stream;
            pt::write_json(params_stream, share_params);
            params = params_stream.str();
        } else if (method == "completepocolrange" && tokens.size() >= 2) {
            int range_id = std::stoi(tokens[1]);
            std::string public_key;
            std::string private_key;
            
            if (tokens.size() >= 3) {
                public_key = tokens[2];
            } else if (!current_public_key.empty()) {
                public_key = current_public_key;
            } else {
                std::cout << "Enter public key: ";
                std::getline(std::cin, public_key);
            }
            
            if (tokens.size() >= 4) {
                private_key = tokens[3];
            } else if (!current_private_key.empty()) {
                private_key = current_private_key;
            } else {
                std::cout << "Enter private key: ";
                std::getline(std::cin, private_key);
            }
            
            // Message to sign (the range ID)
            std::string message = std::to_string(range_id);
            
            // Sign the message
            std::string signature = sign_message(message, private_key);
            
            pt::ptree complete_params;
            complete_params.put("range_id", range_id);
            complete_params.put("public_key", public_key);
            complete_params.put("signature", signature);
            
            std::ostringstream params_stream;
            pt::write_json(params_stream, complete_params);
            params = params_stream.str();
        } else if (method == "getpocolminers") {
            params = "";
        } else if (method == "getpocolrewards") {
            pt::ptree rewards_params;
            if (tokens.size() >= 2) {
                rewards_params.put("public_key", tokens[1]);
            } else if (!current_public_key.empty()) {
                rewards_params.put("public_key", current_public_key);
            }
            
            std::ostringstream params_stream;
            pt::write_json(params_stream, rewards_params);
            params = params_stream.str();
        } else if (method == "getpocolbalance" && tokens.size() >= 2) {
            pt::ptree balance_params;
            balance_params.put("address", tokens[1]);
            
            std::ostringstream params_stream;
            pt::write_json(params_stream, balance_params);
            params = params_stream.str();
        } else if (method == "getpocolutxos" && tokens.size() >= 2) {
            pt::ptree utxos_params;
            utxos_params.put("address", tokens[1]);
            
            std::ostringstream params_stream;
            pt::write_json(params_stream, utxos_params);
            params = params_stream.str();
        } else if (method == "getpocolutxo" && tokens.size() >= 3) {
            pt::ptree utxo_params;
            utxo_params.put("txid", tokens[1]);
            utxo_params.put("index", tokens[2]);
            
            std::ostringstream params_stream;
            pt::write_json(params_stream, utxo_params);
            params = params_stream.str();
        } else if (method == "createcoinbase") {
            // Handle coinbase transaction creation
            std::string address;
            if (tokens.size() >= 2) {
                address = tokens[1];
            } else if (!current_public_key.empty()) {
                address = current_public_key;
            } else {
                std::cout << "Enter address to receive coins: ";
                std::getline(std::cin, address);
            }
            
            pt::ptree coinbase_params;
            coinbase_params.put("address", address);
            
            std::ostringstream params_stream;
            pt::write_json(params_stream, coinbase_params);
            params = params_stream.str();
            
            // Use the createcoinbase RPC method
            method = "createcoinbase";
        } else if (method == "mineblock") {
            // Mine a new block
            std::string public_key;
            std::string private_key;
            
            if (tokens.size() >= 2) {
                public_key = tokens[1];
            } else if (!current_public_key.empty()) {
                public_key = current_public_key;
            } else {
                std::cout << "Enter public key: ";
                std::getline(std::cin, public_key);
            }
            
            if (tokens.size() >= 3) {
                private_key = tokens[2];
            } else if (!current_private_key.empty()) {
                private_key = current_private_key;
            } else {
                std::cout << "Enter private key: ";
                std::getline(std::cin, private_key);
            }
            
            // First, register the miner if not already registered
            std::string message = "register_miner";
            std::string signature = sign_message(message, private_key);
            
            pt::ptree register_params;
            register_params.put("public_key", public_key);
            register_params.put("signature", signature);
            register_params.put("message", message);
            
            std::ostringstream register_params_stream;
            pt::write_json(register_params_stream, register_params);
            std::string register_params_str = register_params_stream.str();
            
            std::string register_response = send_rpc_request(host, port, "registerpocolminer", register_params_str);
            std::cout << "Miner registration: " << register_response << std::endl;
            
            // Get the current template
            std::string template_response = send_rpc_request(host, port, "getpocoltemplate", "");
            std::cout << "Current template: " << template_response << std::endl;
            
            // Request a range to mine
            message = "request_range";
            signature = sign_message(message, private_key);
            
            pt::ptree range_params;
            range_params.put("public_key", public_key);
            range_params.put("signature", signature);
            range_params.put("message", message);
            
            std::ostringstream range_params_stream;
            pt::write_json(range_params_stream, range_params);
            std::string range_params_str = range_params_stream.str();
            
            std::string range_response = send_rpc_request(host, port, "requestpocolrange", range_params_str);
            std::cout << "Range request: " << range_response << std::endl;
            
            // Parse the range response
            std::stringstream range_ss(range_response);
            pt::ptree range_json;
            pt::read_json(range_ss, range_json);
            
            bool success = range_json.get<bool>("success", false);
            if (!success) {
                std::cout << "Failed to request a range to mine." << std::endl;
                continue;
            }
            
            // Get the range details
            int range_id = range_json.get<int>("range_id", 0);
            uint32_t start = range_json.get<uint32_t>("start", 0);
            uint32_t end = range_json.get<uint32_t>("end", 0);
            
            std::cout << "Mining range " << range_id << " from " << start << " to " << end << "..." << std::endl;
            
            // Parse the template response to get the header
            std::stringstream template_ss(template_response);
            pt::ptree template_json;
            pt::read_json(template_ss, template_json);
            
            std::string prev_hash = template_json.get<std::string>("prev_hash", "");
            std::string merkle_root = template_json.get<std::string>("merkle_root", "");
            int64_t timestamp = template_json.get<int64_t>("timestamp", 0);
            
            std::string header = prev_hash + merkle_root + std::to_string(timestamp);
            
            // Simulate mining by trying a few nonces
            for (uint32_t nonce = start; nonce < start + 1000 && nonce < end; ++nonce) {
                // Sign the share data
                std::string share_message = header + std::to_string(nonce);
                std::string share_signature = sign_message(share_message, private_key);
                
                // Submit a share for this nonce
                pt::ptree share_params;
                share_params.put("header", header);
                share_params.put("nonce", nonce);
                share_params.put("public_key", public_key);
                share_params.put("signature", share_signature);
                
                std::ostringstream share_params_stream;
                pt::write_json(share_params_stream, share_params);
                std::string share_params_str = share_params_stream.str();
                
                std::string share_response = send_rpc_request(host, port, "submitpocolshare", share_params_str);
                std::cout << "Share submission: " << share_response << std::endl;
                
                // Check if we found a block
                std::stringstream share_ss(share_response);
                pt::ptree share_json;
                pt::read_json(share_ss, share_json);
                
                bool found_block = share_json.get<bool>("found_block", false);
                if (found_block) {
                    std::string block_hash = share_json.get<std::string>("block_hash", "");
                    std::cout << "Found a block! Hash: " << block_hash << std::endl;
                    break;
                }
            }
            
            // Complete the range
            std::string complete_message = std::to_string(range_id);
            std::string complete_signature = sign_message(complete_message, private_key);
            
            pt::ptree complete_params;
            complete_params.put("range_id", range_id);
            complete_params.put("public_key", public_key);
            complete_params.put("signature", complete_signature);
            
            std::ostringstream complete_params_stream;
            pt::write_json(complete_params_stream, complete_params);
            std::string complete_params_str = complete_params_stream.str();
            
            std::string complete_response = send_rpc_request(host, port, "completepocolrange", complete_params_str);
            std::cout << "Range completion: " << complete_response << std::endl;
            
            std::cout << "Mining simulation complete." << std::endl;
            continue;
        } else if (method == "createpocoltransaction") {
            // Interactive transaction creation
            pt::ptree tx_params;
            pt::ptree inputs_array;
            pt::ptree outputs_array;
            
            // Get inputs
            std::cout << "Enter number of inputs: ";
            int num_inputs;
            std::cin >> num_inputs;
            std::cin.ignore(); // Clear the newline
            
            for (int i = 0; i < num_inputs; ++i) {
                std::cout << "Enter input " << (i + 1) << " (txid:index): ";
                std::string input;
                std::getline(std::cin, input);
                
                pt::ptree input_node;
                input_node.put("", input);
                inputs_array.push_back(std::make_pair("", input_node));
            }
            
            // Get outputs
            std::cout << "Enter number of outputs: ";
            int num_outputs;
            std::cin >> num_outputs;
            std::cin.ignore(); // Clear the newline
            
            for (int i = 0; i < num_outputs; ++i) {
                std::cout << "Enter output " << (i + 1) << " (address:amount): ";
                std::string output;
                std::getline(std::cin, output);
                
                pt::ptree output_node;
                output_node.put("", output);
                outputs_array.push_back(std::make_pair("", output_node));
            }
            
            // Get fee
            std::cout << "Enter fee: ";
            int64_t fee;
            std::cin >> fee;
            std::cin.ignore(); // Clear the newline
            
            // Get private key
            std::string private_key;
            if (!current_private_key.empty()) {
                private_key = current_private_key;
                std::cout << "Using current private key." << std::endl;
            } else {
                std::cout << "Enter private key: ";
                std::getline(std::cin, private_key);
            }
            
            tx_params.add_child("inputs", inputs_array);
            tx_params.add_child("outputs", outputs_array);
            tx_params.put("fee", fee);
            tx_params.put("private_key", private_key);
            
            std::ostringstream params_stream;
            pt::write_json(params_stream, tx_params);
            params = params_stream.str();
        } else if (method == "getpocoltransaction" && tokens.size() >= 2) {
            pt::ptree tx_params;
            tx_params.put("txid", tokens[1]);
            
            std::ostringstream params_stream;
            pt::write_json(params_stream, tx_params);
            params = params_stream.str();
        } else if (method == "generatekeypair") {
            // This is a client-side operation, no need to send to the server
            std::cout << "Generating new key pair..." << std::endl;
            
            // For simplicity, we'll just generate random strings
            // In a real implementation, this would use proper cryptographic key generation
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 15);
            
            const char* hex_chars = "0123456789abcdef";
            
            std::string private_key;
            
            // Generate a 64-character private key (256 bits)
            for (int i = 0; i < 64; ++i) {
                private_key += hex_chars[dis(gen)];
            }
            
            // Generate the public key from the private key
            // In a real implementation, this would use proper public key derivation
            // For our simplified implementation, we'll just hash the private key
            std::string public_key_binary = pocol::compute_sha256(private_key);

            // Extend the public key to make it look more realistic
            while (public_key_binary.length() < 64) {
                public_key_binary += pocol::compute_sha256(public_key_binary);
            }
            public_key_binary = public_key_binary.substr(0, 64);

            // Convert binary public key to hexadecimal string for display
            std::string public_key = "";
            for (unsigned char c : public_key_binary) {
                char hex[3];
                sprintf(hex, "%02x", static_cast<unsigned char>(c));
                public_key += hex;
            }
            
            // Store the key pair for convenience
            current_private_key = private_key;
            current_public_key = public_key;
            
            std::cout << "Private Key: " << private_key << std::endl;
            std::cout << "Public Key: " << public_key << std::endl;
            std::cout << "IMPORTANT: Save your private key securely. It will not be shown again." << std::endl;
            std::cout << "NOTE: This key pair has been stored for use in subsequent commands." << std::endl;
            
            continue; // Skip sending to server
        } else {
            std::cout << "Unknown command or invalid parameters. Type 'help' for available commands." << std::endl;
            continue;
        }
        
        // Send request and print response
        std::string response = send_rpc_request(host, port, method, params);
        std::cout << response << std::endl;
    }
    
    return 0;
}
