#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include "messages.pb.h"

namespace pocol {

// Simple wrapper functions for Protocol Buffers to avoid direct usage of Abseil hash functions

// Serialize a Protocol Buffers message to a string
template <typename T>
inline std::string serialize_proto(const T& message) {
    std::string serialized;
    message.SerializeToString(&serialized);
    return serialized;
}

// Parse a Protocol Buffers message from a string
template <typename T>
inline bool parse_proto(const std::string& serialized, T& message) {
    return message.ParseFromString(serialized);
}

// Create a string map from a Protocol Buffers map
template <typename T>
inline std::unordered_map<std::string, T> proto_map_to_std_map(const google::protobuf::Map<std::string, T>& proto_map) {
    std::unordered_map<std::string, T> std_map;
    for (const auto& pair : proto_map) {
        std_map[pair.first] = pair.second;
    }
    return std_map;
}

// Create a Protocol Buffers map from a string map
template <typename T>
inline void std_map_to_proto_map(const std::unordered_map<std::string, T>& std_map, google::protobuf::Map<std::string, T>* proto_map) {
    for (const auto& pair : std_map) {
        (*proto_map)[pair.first] = pair.second;
    }
}

} // namespace pocol
