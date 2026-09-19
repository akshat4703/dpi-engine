#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include "dpi_engine.h"

using namespace DPI;

void printUsage(const char* program) {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v1.0                            ║
║               Deep Packet Inspection System                   ║
╚══════════════════════════════════════════════════════════════╝

Usage: )" << program << R"( <input.pcap> <output.pcap> [options]

Arguments:
  input.pcap     Input PCAP file (captured user traffic)
  output.pcap    Output PCAP file (filtered traffic to internet)

Options:
  --block-ip <ip>        Block packets from source IP
  --block-app <app>      Block application (e.g., YouTube, Facebook)
  --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)
  --block-port <port>    Block destination port (1-65535)
  --rules <file>         Load blocking rules from file
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)
  --verbose              Enable verbose output

Examples:
  )" << program << R"( capture.pcap filtered.pcap
  )" << program << R"( capture.pcap filtered.pcap --block-app YouTube
  )" << program << R"( capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com
  )" << program << R"( capture.pcap filtered.pcap --block-port 8080
  )" << program << R"( capture.pcap filtered.pcap --rules blocking_rules.txt

Supported Apps for Blocking:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub

Architecture:
  ┌─────────────┐
  │ PCAP Reader │  Reads packets from input file
  └──────┬──────┘
         │ hash(5-tuple) % num_lbs
         ▼
  ┌──────┴──────┐
  │ Load Balancer │  2 LB threads distribute to FPs
  │   LB0 │ LB1   │
  └──┬────┴────┬──┘
     │         │  hash(5-tuple) % fps_per_lb
     ▼         ▼
  ┌──┴──┐   ┌──┴──┐
  │FP0-1│   │FP2-3│  4 FP threads: DPI, classification, blocking
  └──┬──┘   └──┬──┘
     │         │
     ▼         ▼
  ┌──┴─────────┴──┐
  │ Output Writer │  Writes forwarded packets to output
  └───────────────┘

)";
}

std::vector<std::string> split(const std::string& s) {
    std::vector<std::string> tokens;
    std::istringstream iss(s);
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

int main(int argc, char* argv[]) {
    // Handle --help before the positional-argument check. The option loop below
    // starts at argv[3], so a bare "--help" would otherwise never reach it and
    // would exit 1 as a usage error.
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        }
    }

    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];
    
    // Parse options
    DPIEngine::Config config;
    config.num_load_balancers = 2;
    config.fps_per_lb = 2;
    
    std::vector<std::string> block_ips;
    std::vector<std::string> block_apps;
    std::vector<std::string> block_domains;
    std::vector<uint16_t> block_ports;
    std::string rules_file;
    
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--block-ip" && i + 1 < argc) {
            block_ips.push_back(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
            block_apps.push_back(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            block_domains.push_back(argv[++i]);
        } else if (arg == "--block-port" && i + 1 < argc) {
            const std::string value = argv[++i];
            try {
                size_t consumed = 0;
                const int port = std::stoi(value, &consumed);
                if (consumed != value.size() || port < 1 || port > 65535) {
                    throw std::invalid_argument("out of range");
                }
                block_ports.push_back(static_cast<uint16_t>(port));
            } catch (const std::exception&) {
                std::cerr << "Invalid port '" << value
                          << "' (expected an integer in 1-65535)\n";
                return 1;
            }
        } else if (arg == "--rules" && i + 1 < argc) {
            rules_file = argv[++i];
        } else if (arg == "--lbs" && i + 1 < argc) {
            config.num_load_balancers = std::stoi(argv[++i]);
        } else if (arg == "--fps" && i + 1 < argc) {
            config.fps_per_lb = std::stoi(argv[++i]);
        } else if (arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        }
    }
    
    // Create DPI engine
    DPIEngine engine(config);
    
    // Initialize
    if (!engine.initialize()) {
        std::cerr << "Failed to initialize DPI engine\n";
        return 1;
    }
    
    // Load rules from file if specified
    if (!rules_file.empty()) {
        engine.loadRules(rules_file);
    }
    
    // Apply command-line blocking rules
    for (const auto& ip : block_ips) {
        engine.blockIP(ip);
    }
    
    for (const auto& app : block_apps) {
        engine.blockApp(app);
    }
    
    for (const auto& domain : block_domains) {
        engine.blockDomain(domain);
    }

    for (uint16_t port : block_ports) {
        engine.blockPort(port);
    }

    // Process the file
    if (!engine.processFile(input_file, output_file)) {
        std::cerr << "Failed to process file\n";
        return 1;
    }
    
    std::cout << "\nProcessing complete!\n";
    std::cout << "Output written to: " << output_file << "\n";
    
    return 0;
}
