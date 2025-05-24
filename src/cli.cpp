#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "../include/crypto_utils.hpp"
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

namespace http = boost::beast::http;
namespace pt = boost::property_tree;

// Function to send JSON-RPC request
std::string send_rpc_request(const std::string& host, uint16_t port, 
                            const std::string& method, const std::string& params) {
    try {
        std::cout << "DEBUG: Starting RPC request to " << host << ":" << port << std::endl;
        std::cout << "DEBUG: Method: " << method << std::endl;
        std::cout << "DEBUG: Params: " << params << std::endl;
        
        // Record start time
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Set up connection
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::resolver resolver(io_context);
        boost::asio::ip::tcp::socket socket(io_context);
        
        std::cout << "DEBUG: Resolving host..." << std::endl;
        boost::system::error_code ec;
        auto const results = resolver.resolve(host, std::to_string(port), ec);
        if (ec) {
            std::cout << "DEBUG: Error resolving host: " << ec.message() << std::endl;
            return std::string("Error resolving host: ") + ec.message();
        }
        
        std::cout << "DEBUG: Connecting to host..." << std::endl;
        boost::asio::connect(socket, results.begin(), results.end(), ec);
        if (ec) {
            std::cout << "DEBUG: Error connecting to host: " << ec.message() << std::endl;
            return std::string("Error connecting to host: ") + ec.message();
        }
        
        // Prepare JSON-RPC request
        pt::ptree request;
        request.put("jsonrpc", "2.0");
        request.put("method", method);
        request.put("params", params);
        request.put("id", 1);
        
        std::ostringstream request_stream;
        pt::write_json(request_stream, request);
        std::string request_body = request_stream.str();
        
        std::cout << "DEBUG: Request body: " << request_body << std::endl;
        
        // Prepare HTTP request
        http::request<http::string_body> req{http::verb::post, "/", 11};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, "pocol-cli");
        req.set(http::field::content_type, "application/json");
        req.set(http::field::content_length, std::to_string(request_body.size()));
        req.body() = request_body;
        
        // Send request
        std::cout << "DEBUG: Sending request..." << std::endl;
        http::write(socket, req, ec);
        if (ec) {
            std::cout << "DEBUG: Error sending request: " << ec.message() << std::endl;
            return std::string("Error sending request: ") + ec.message();
        }
        
        // Receive response
        std::cout << "DEBUG: Waiting for response..." << std::endl;
        boost::beast::flat_buffer buffer;
        http::response<http::string_body> res;
        
        // Set a timeout for reading the response (5 seconds)
        //socket.set_option(boost::asio::socket_base::receive_timeout(boost::asio::chrono::seconds(5)), ec);
        //if (ec) {
        //    std::cout << "DEBUG: Error setting socket timeout: " << ec.message() << std::endl;
        //}
        
        // Set a timeout using SO_RCVTIMEO socket option (more widely supported)
#ifdef _WIN32
    DWORD timeout = 5000; // 5 seconds in milliseconds
    setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 5;  // 5 seconds timeout
    tv.tv_usec = 0;
    setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif
std::cout << "DEBUG: Socket timeout set" << std::endl;
        
        http::read(socket, buffer, res, ec);
        if (ec) {
            std::cout << "DEBUG: Error reading response: " << ec.message() << std::endl;
            return std::string("Error reading response: ") + ec.message();
        }
        
        // Record end time and calculate duration
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        
        // Print debug information
        std::cout << "DEBUG: Request completed in " << duration << " ms" << std::endl;
        std::cout << "HTTP Status: " << res.result_int() << " " << res.reason() << std::endl;
        std::cout << "Response Headers:" << std::endl;
        for (auto const& field : res.base()) {
            std::cout << "  " << field.name() << ": " << field.value() << std::endl;
        }
        
        std::cout << "DEBUG: Raw response body:" << std::endl;
        std::cout << res.body() << std::endl;
        
        // Close connection
        std::cout << "DEBUG: Closing connection..." << std::endl;
        socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != boost::asio::error::not_connected) {
            std::cout << "DEBUG: Error shutting down socket: " << ec.message() << std::endl;
        }
        
        return res.body();
    } catch (const std::exception& e) {
        std::cout << "DEBUG: Exception caught: " << e.what() << std::endl;
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
    std::cout << "  listutxos                         - List all available UTXOs in the system" << std::endl;
    std::cout << "  gettransactionoutputs <txid>      - Get all outputs for a specific transaction" << std::endl;
    std::cout << "  getmempool                        - View all transactions in the mempool" << std::endl;
    std::cout << "  getmempoolinfo                    - Get mempool statistics and information" << std::endl;
    std::cout << "  help                              - Show this help message" << std::endl;
    std::cout << "  exit                              - Exit the CLI" << std::endl;
}

// Helper function to convert binary data to hex string
std::string binary_to_hex(const std::string& binary) {
    std::string hex;
    for (unsigned char c : binary) {
        char buf[3];
        sprintf(buf, "%02x", static_cast<unsigned char>(c));
        hex += buf;
    }
    return hex;
}

// Function to sign a message with a private key
std::string sign_message(const std::string& message, const std::string& private_key) {
    // In a real implementation, this would use proper cryptographic signing
    // For our simplified implementation, we'll just concatenate the message and private key and hash it
    std::string binary_signature = pocol::compute_sha256(message + private_key);
    
    // Convert the binary signature to a hexadecimal string
    return binary_to_hex(binary_signature);
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
            
            // Create the JSON object manually to ensure proper formatting
            std::string json_params = "{\"public_key\":\"" + public_key + 
                             "\",\"signature\":\"" + signature + 
                             "\",\"message\":\"" + message + "\"}";
            
            params = json_params;
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
            
            // Create the JSON object manually to ensure proper formatting
            std::string json_params = "{\"public_key\":\"" + public_key + 
                             "\",\"signature\":\"" + signature + 
                             "\",\"message\":\"" + message + "\"}";
            
            params = json_params;
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
            
            // Create the JSON object manually to ensure proper formatting
            std::string json_params = "{\"header\":\"" + header + 
                             "\",\"nonce\":" + std::to_string(nonce) + 
                             ",\"public_key\":\"" + public_key + 
                             "\",\"signature\":\"" + signature + "\"}";
            
            params = json_params;
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
            
            // Create the JSON object manually to ensure proper formatting
            std::string json_params = "{\"range_id\":" + std::to_string(range_id) + 
                             ",\"public_key\":\"" + public_key + 
                             "\",\"signature\":\"" + signature + "\"}";
            
            params = json_params;
        } else if (method == "getpocolminers") {
            params = "";
        } else if (method == "getpocolrewards") {
            std::string public_key;
            
            if (tokens.size() >= 2) {
                public_key = tokens[1];
            } else if (!current_public_key.empty()) {
                public_key = current_public_key;
            } else {
                std::cout << "Enter public key: ";
                std::getline(std::cin, public_key);
            }
            
            // Create the JSON object manually to ensure proper formatting
            std::string json_params = "{\"public_key\":\"" + public_key + "\"}";
            
            params = json_params;
        } else if (method == "getpocolbalance" && tokens.size() >= 2) {
            std::string address = tokens[1];
            
            // Create the JSON object manually to ensure proper formatting
            std::string json_params = "{\"address\":\"" + address + "\"}";
            
            params = json_params;
        } else if (method == "getpocolutxos" && tokens.size() >= 2) {
            std::string address = tokens[1];
            
            // Create the JSON object manually to ensure proper formatting
            std::string json_params = "{\"address\":\"" + address + "\"}";
            
            params = json_params;
        } else if (method == "getpocolutxo" && tokens.size() >= 3) {
            std::string txid = tokens[1];
            std::string index = tokens[2];
            
            // Create the JSON object manually to ensure proper formatting
            std::string json_params = "{\"txid\":\"" + txid + "\",\"index\":" + index + "}";
            
            params = json_params;
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
            
            // Create the JSON object manually to ensure proper formatting
            std::string json_params = "{\"address\":\"" + address + "\"}";
            
            params = json_params;
            
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
            
            // Create the JSON object manually to ensure proper formatting
            std::string register_params_str = "{\"public_key\":\"" + public_key + 
                                    "\",\"signature\":\"" + signature + 
                                    "\",\"message\":\"" + message + "\"}";
            
            std::string register_response = send_rpc_request(host, port, "registerpocolminer", register_params_str);
            std::cout << "Miner registration: " << register_response << std::endl;
            
            // Get the current template
            std::string template_response = send_rpc_request(host, port, "getpocoltemplate", "");
            std::cout << "Current template: " << template_response << std::endl;
            
            // Request a range to mine
            message = "request_range";
            signature = sign_message(message, private_key);
            
            // Create the JSON object manually to ensure proper formatting
            std::string range_params_str = "{\"public_key\":\"" + public_key + 
                                 "\",\"signature\":\"" + signature + 
                                 "\",\"message\":\"" + message + "\"}";
            
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
                
                // Create the JSON object manually to ensure proper formatting
                std::string share_params_str = "{\"header\":\"" + header + 
                                    "\",\"nonce\":" + std::to_string(nonce) + 
                                    ",\"public_key\":\"" + public_key + 
                                    "\",\"signature\":\"" + share_signature + "\"}";
                
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
            
            // Create the JSON object manually to ensure proper formatting
            std::string complete_params_str = "{\"range_id\":" + std::to_string(range_id) + 
                                   ",\"public_key\":\"" + public_key + 
                                   "\",\"signature\":\"" + complete_signature + "\"}";
            
            std::string complete_response = send_rpc_request(host, port, "completepocolrange", complete_params_str);
            std::cout << "Range completion: " << complete_response << std::endl;
            
            std::cout << "Mining simulation complete." << std::endl;
            continue;
        } else if (method == "createpocoltransaction") {
            // Interactive transaction creation
            std::cout << "Enter number of inputs: ";
            int num_inputs;
            std::cin >> num_inputs;
            std::cin.ignore(); // Clear the newline
            
            std::string inputs_json = "[";
            for (int i = 0; i < num_inputs; ++i) {
                std::cout << "Enter input " << (i + 1) << " (txid:index): ";
                std::string input;
                std::getline(std::cin, input);
                
                if (i > 0) inputs_json += ",";
                inputs_json += "\"" + input + "\"";
            }
            inputs_json += "]";
            
            // Get outputs
            std::cout << "Enter number of outputs: ";
            int num_outputs;
            std::cin >> num_outputs;
            std::cin.ignore(); // Clear the newline
            
            std::string outputs_json = "[";
            for (int i = 0; i < num_outputs; ++i) {
                std::cout << "Enter output " << (i + 1) << " (address:amount): ";
                std::string output;
                std::getline(std::cin, output);
                
                if (i > 0) outputs_json += ",";
                outputs_json += "\"" + output + "\"";
            }
            outputs_json += "]";
            
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
            
            // Create the JSON object manually to ensure proper formatting
            std::string json_params = "{\"inputs\":" + inputs_json + 
                             ",\"outputs\":" + outputs_json + 
                             ",\"fee\":" + std::to_string(fee) + 
                             ",\"private_key\":\"" + private_key + "\"}";
            
            params = json_params;
        } else if (method == "getpocoltransaction" && tokens.size() >= 2) {
            std::string txid = tokens[1];
            
            // Create the JSON object manually to ensure proper formatting
            std::string json_params = "{\"txid\":\"" + txid + "\"}";
            
            params = json_params;
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

            // Convert the binary hash to a hexadecimal string
            std::string public_key = binary_to_hex(public_key_binary);

            // Extend the public key to make it look more realistic
            std::string extended_public_key = public_key;
            for (int i = 0; i < 3 && extended_public_key.length() < 128; ++i) {
                std::string next_hash_binary = pocol::compute_sha256(extended_public_key);
                extended_public_key += binary_to_hex(next_hash_binary);
            }
            public_key = extended_public_key.substr(0, 128);
            
            // Store the key pair for convenience
            current_private_key = private_key;
            current_public_key = public_key;
            
            std::cout << "Private Key: " << private_key << std::endl;
            std::cout << "Public Key: " << public_key << std::endl;
            std::cout << "IMPORTANT: Save your private key securely. It will not be shown again." << std::endl;
            std::cout << "NOTE: This key pair has been stored for use in subsequent commands." << std::endl;
            
            continue; // Skip sending to server
        } else if (method == "listutxos") {
            params = "";
        } else if (method == "gettransactionoutputs" && tokens.size() >= 2) {
            std::string txid = tokens[1];
            
            // Create the JSON object manually to ensure proper formatting
            std::string json_params = "{\"txid\":\"" + txid + "\"}";
            
            params = json_params;
        } else if (method == "getmempool") {
            params = "";
        } else if (method == "getmempoolinfo") {
            params = "";
        } else {
            std::cout << "Unknown command or invalid parameters. Type 'help' for available commands." << std::endl;
            continue;
        }
        
        // Send request and print response
        std::cout << "Sending request: Method=" << method << ", Params=" << params << std::endl;
        std::string response = send_rpc_request(host, port, method, params);
        std::cout << response << std::endl;
    }
    
    return 0;
}
