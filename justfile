####################################################################################################
# Build lifecycle
####################################################################################################

# Build the project (default recipe)
build:
    if ! test -d build; then \
        conan install . --output-folder=build --build=missing --profile:all=profiles/detect; \
        cmake -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
            -DCMAKE_BUILD_TYPE=Release; \
    fi

    cmake --build build

# Grant the binary the necessary capabilities
[linux]
caps: build
    setcap cap_net_raw,cap_net_admin+ep ./build/nab

# Build and run the main executable
run *ARGS: build
    ./build/nab {{ ARGS }}

# Full clean rebuild
rebuild: clean build

# Remove build artifacts
clean:
    rm -rf build

####################################################################################################
# Testing and quality
####################################################################################################

# Run tests, lints, format checking, and spell checking to match CI
all-checks: (test '--progress') lint fmt-check spell-check

# Build and run tests
test *ARGS: build
    ctest --test-dir build --output-on-failure {{ ARGS }}

# Build and lint with Clang-Tidy
lint: build
    clang-tidy -p build --quiet --use-color --warnings-as-errors='*' \
        $(jq -r '.[].file' build/compile_commands.json | sort -u)

# Check formatting with Clang-Format
fmt-check:
    git ls-files -z '*.cpp' '*.hpp' | xargs -0 clang-format --dry-run --Werror \
        && echo 'Formatting check passed'

# Check spelling with Codebook
spell-check:
    git ls-files -z | xargs -0 codebook-lsp lint

####################################################################################################
# Other convenience
####################################################################################################

# Read a PCAP file with Termshark (if present) or TShark
inspect pcap:
    @if command -v termshark >/dev/null 2>&1; then termshark -r {{ pcap }}; \
    elif command -v tshark >/dev/null 2>&1; then tshark -r {{ pcap }}; \
    else echo 'Neither termshark nor tshark found' >&2; exit 1; \
    fi
