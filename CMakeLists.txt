cmake_minimum_required(VERSION 3.14)
project(pocol VERSION 0.1.0 LANGUAGES CXX)

# Set C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Suppress the <ciso646> warning
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wno-cpp)
endif()

# Find required packages
find_package(Boost REQUIRED COMPONENTS system thread)
find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# Add library target
add_library(pocol_lib
    src/network.cpp
    src/mempool.cpp
    src/template_builder.cpp
    src/miner.cpp
    src/rpc.cpp
    src/share_manager.cpp
    src/message_types.cpp
    src/transaction_utils.cpp
    src/utxo_set.cpp
    src/string_utils.cpp
)

# Link libraries
target_link_libraries(pocol_lib
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)

# Add Windows-specific libraries if on Windows
if(WIN32)
    target_link_libraries(pocol_lib ws2_32 mswsock)
endif()

# Add executable target
add_executable(pocold src/main.cpp)
target_link_libraries(pocold pocol_lib)

# Add CLI executable
add_executable(pocol-cli src/cli.cpp)
target_link_libraries(pocol-cli pocol_lib)

# Add tests
enable_testing()
add_executable(pocol_tests
    test/network_test.cpp
    test/mempool_test.cpp
    test/template_builder_test.cpp
    test/miner_test.cpp
    test/share_manager_test.cpp
)
target_link_libraries(pocol_tests
    pocol_lib
    GTest::GTest
    GTest::Main
)
add_test(NAME pocol_tests COMMAND pocol_tests)

# Install targets
install(TARGETS pocold pocol-cli
    RUNTIME DESTINATION bin
)
