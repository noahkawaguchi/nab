# Build and run (default recipe)
run:
    cmake --build build
    ./build/nab

# Full clean rebuild
rebuild:
    rm -rf build
    conan install . --output-folder=build --build=missing
    cmake -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
    cmake --build build
