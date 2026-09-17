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
              if pkgs.stdenv.isLinux then
                ''
                  export CC=${pkgs.gcc}/bin/gcc
                  export CXX=${pkgs.gcc}/bin/g++

                  export CLANG_TIDY_EXTRA_ARGS="--extra-arg=--gcc-toolchain=${pkgs.gcc.cc}"
                ''
              else if pkgs.stdenv.isDarwin then
                ''
                  export CC=${pkgs.clang}/bin/clang
                  export CXX=${pkgs.clang}/bin/clang++
                ''
              else
                "";
          };
        }
      );
    };
}
