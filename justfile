# Regular iterative build (default recipe)
build:
    cmake --build build

# Full clean rebuild
rebuild: && build
    rm -rf build
    conan install . --output-folder=build --build=missing
    cmake -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
