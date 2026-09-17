{
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    {
      devShells = nixpkgs.lib.genAttrs [ "aarch64-linux" "x86_64-linux" "aarch64-darwin" ] (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              clang-tools
              cmake
              codebook
              conan
              jq
              just
              termshark
            ];

            shellHook =
              # Clang-Tidy does its own separate GCC toolchain auto-detection, which finds the
              # system libstdc++ in CI independent of the CC/CXX environment variables, so pass this
              # through to be read in the `justfile` recipe
              if pkgs.stdenv.isLinux then
                ''
                  export CLANG_TIDY_EXTRA_ARGS="--extra-arg=--gcc-toolchain=${pkgs.gcc.cc}"
                ''
              else
                "";
          };
        }
      );
    };
}
