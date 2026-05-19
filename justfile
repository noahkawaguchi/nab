# Regular iterative build (default recipe)
build:
    cmake --build build

# Build and run the main executable
run *ARGS: build
    ./build/nab {{ARGS}}

# Full clean rebuild
rebuild: clean && build
    conan install . --output-folder=build --build=missing
    cmake -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release

# Build and run tests
test: build
    ctest --test-dir build --output-on-failure

# Lint with Clang-Tidy
lint: build
    run-clang-tidy -p build -quiet -use-color -warnings-as-errors '*'

# Remove build artifacts
clean:
    rm -rf build
