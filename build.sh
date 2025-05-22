#!/bin/bash

# Create build directory if it doesn't exist
mkdir -p build
cd build

# Run CMake
echo "Running CMake..."
cmake -DCMAKE_BUILD_TYPE=Release ..

# Build the project
echo "Building project..."
cmake --build . -- -j$(nproc)

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo
    echo "To run the daemon: ./pocold --p2p-port 8333 --rpc-port 8332 --miner-id your-miner-id"
    echo "To run the tests: ctest"
else
    echo "Build failed with error code $?"
fi

cd ..
