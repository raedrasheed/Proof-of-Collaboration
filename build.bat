@echo off
echo Building PoCol Blockchain with MinGW64...

REM Create build directory if it doesn't exist
if not exist build mkdir build
cd build

REM Run CMake
echo Running CMake...
cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release ..

REM Build the project
echo Building project...
cmake --build . -- -j4

REM Check if build was successful
if %ERRORLEVEL% EQU 0 (
    echo Build successful!
    echo.
    echo To run the daemon: pocold.exe --p2p-port 8333 --rpc-port 8332 --miner-id your-miner-id
    echo To run the tests: ctest
) else (
    echo Build failed with error code %ERRORLEVEL%
)

cd ..
