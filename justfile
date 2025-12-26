# Regular iterative build (default recipe)
build:
    cmake --build build

# Run tests
test: build
    ctest --test-dir build --output-on-failure

# Full clean rebuild
rebuild: clean && build
    conan install . --output-folder=build --build=missing
    cmake -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release

# Remove build artifacts
clean:
    rm -rf build
