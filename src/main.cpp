#include <iostream>
#include <memory>
#include <thread>
#include <csignal>
#include "../include/network.hpp"
#include "../include/mempool.hpp"
#include "../include/template_builder.hpp"
#include "../include/miner.hpp"
#include "../include/share_manager.hpp"
#include "../include/rpc.hpp"

using namespace pocol;

// Global flag for graceful shutdown
volatile sig_atomic_t running = 1;

// Signal handler
void signal_handler(int signal) {
    std::cout << "Received signal " << signal << ", shutting down..." << std::endl;
    running = 0;
}

int main(int argc, char* argv[]) {
    // Register signal handler
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    
    try {
        // Parse command line arguments
        uint16_t p2p_port = 8333;
        uint16_t rpc_port = 8332;
        std::string miner_id = "miner1";
        
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--p2p-port" && i + 1 < argc) {
                p2p_port = std::stoi(argv[++i]);
            } else if (arg == "--rpc-port" && i + 1 < argc) {
                rpc_port = std::stoi(argv[++i]);
            } else if (arg == "--miner-id" && i + 1 < argc) {
                miner_id = argv[++i];
            }
        }
        
        std::cout << "Starting PoCol daemon..." << std::endl;
        std::cout << "P2P Port: " << p2p_port << std::endl;
        std::cout << "RPC Port: " << rpc_port << std::endl;
        std::cout << "Miner ID: " << miner_id << std::endl;
        
        // Create components
        auto network = std::make_shared<Network>(p2p_port);
        auto mempool = std::make_shared<Mempool>();
        auto template_builder = std::make_shared<TemplateBuilder>(mempool);
        auto share_manager = std::make_shared<ShareManager>();
        auto miner = std::make_shared<Miner>(network, template_builder);
        auto rpc = std::make_shared<RPC>(rpc_port, template_builder, miner, share_manager);
        
        // Set miner ID
        miner->set_miner_id(miner_id);
        
        // Start components
        network->start();
        miner->start();
        rpc->start();
        
        // Main loop
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        // Stop components
        rpc->stop();
        miner->stop();
        network->stop();
        
        std::cout << "PoCol daemon stopped." << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
