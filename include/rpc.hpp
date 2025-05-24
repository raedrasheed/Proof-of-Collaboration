#pragma once

#include <string>
#include <functional>
#include <unordered_map>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include "message_types.hpp"
#include "template_builder.hpp"
#include "miner.hpp"
#include "share_manager.hpp"

namespace pocol {

class RPC {
public:
    RPC(uint16_t port, 
        std::shared_ptr<TemplateBuilder> template_builder,
        std::shared_ptr<Miner> miner,
        std::shared_ptr<ShareManager> share_manager);
    ~RPC();

    // Start RPC server
    void start();
    
    // Stop RPC server
    void stop();

private:
    // Handle HTTP request
    void handle_request(boost::beast::http::request<boost::beast::http::string_body>& req,
                       boost::beast::http::response<boost::beast::http::string_body>& res);
    
    // Parse JSON-RPC request
    bool parse_json_rpc(const std::string& body, std::string& method, std::string& params, int& id);
    
    // Accept new connections
    void accept_connections();
    
    // RPC methods
    std::string get_pocol_template();
    std::string request_pocol_range(const std::string& params);
    std::string submit_pocol_share(const std::string& params);
    std::string get_pocol_balance(const std::string& params);
    std::string create_pocol_transaction(const std::string& params);
    std::string get_pocol_transaction(const std::string& params);
    std::string get_pocol_utxos(const std::string& params);
    std::string get_pocol_utxo(const std::string& params);
    std::string create_coinbase_transaction(const std::string& params);
    std::string register_pocol_miner(const std::string& params);
    std::string get_pocol_rewards(const std::string& params);
    std::string get_pocol_miners(const std::string& params);
    std::string complete_pocol_range(const std::string& params);
    
    std::string list_all_utxos(const std::string& params);
    std::string get_transaction_outputs(const std::string& params);
    std::string get_mempool(const std::string& params);
    std::string get_mempool_info(const std::string& params);

    // Helper method to get all addresses with UTXOs
    std::vector<std::string> get_all_addresses();
    
    // Transaction history methods
    void store_transaction_history(const Transaction& tx);
    Transaction get_transaction_history(const std::string& txid);

    boost::asio::io_context io_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<TemplateBuilder> template_builder_;
    std::shared_ptr<Miner> miner_;
    std::shared_ptr<ShareManager> share_manager_;
    std::unordered_map<std::string, std::function<std::string(const std::string&)>> rpc_methods_;
    bool is_running_;
};

} // namespace pocol
