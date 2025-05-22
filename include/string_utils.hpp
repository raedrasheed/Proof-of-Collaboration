#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace pocol {

// Helper function to convert binary data to hex string
std::string bytes_to_hex_string(const std::string& input);

// Helper function to reverse byte order (for Bitcoin-style txid)
std::string reverse_bytes(const std::string& input);

} // namespace pocol
