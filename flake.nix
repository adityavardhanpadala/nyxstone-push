{
  description = "Nyxstone – LLVM-based assembler/disassembler";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-darwin" "x86_64-darwin" ];

      forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system:
        f {
          inherit system;
          pkgs = import nixpkgs { inherit system; };
        }
      );

      llvmVersions = [ 16 17 18 ];

      # Build a dev shell for a given LLVM version
      mkDevShell = { pkgs, llvmVersion }:
        let
          llvmPkgs = pkgs.${"llvmPackages_${toString llvmVersion}"};
        in
        pkgs.mkShell.override { stdenv = llvmPkgs.stdenv; } {
          packages = with pkgs; [
            llvmPkgs.llvm
            llvmPkgs.clang-tools
            cmake
            ninja
            pkg-config
            zlib
            zstd
            libxml2
            rustc
            cargo
            rustfmt
            clippy
            python3
            python3Packages.pybind11
            python3Packages.setuptools
            uv
            cppcheck
          ];

          shellHook = ''
            export NYXSTONE_LLVM_PREFIX=${llvmPkgs.llvm.dev}
            export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath [ llvmPkgs.llvm pkgs.zlib pkgs.zstd ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
          '';
        };

      # Build a pure C++ check derivation for a given LLVM version
      mkCppCheck = { pkgs, llvmVersion }:
        let
          llvmPkgs = pkgs.${"llvmPackages_${toString llvmVersion}"};
        in
        llvmPkgs.stdenv.mkDerivation {
          pname = "nyxstone-cpp-llvm${toString llvmVersion}";
          version = "0.1.0";

          src = self;

          nativeBuildInputs = [ pkgs.cmake pkgs.ninja ];

          buildInputs = [
            llvmPkgs.llvm
            pkgs.zlib
            pkgs.zstd
          ];

          cmakeFlags = [
            "-DNYXSTONE_BUILD_EXAMPLES=ON"
          ];

          doCheck = true;

          checkPhase = ''
            runHook preCheck
            ctest --output-on-failure
            runHook postCheck
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out
            touch $out/success
            runHook postInstall
          '';
        };
    in
    {
      devShells = forAllSystems ({ pkgs, system }: {
        default = mkDevShell { inherit pkgs; llvmVersion = 18; };
      } // builtins.listToAttrs (map (v: {
        name = "llvm${toString v}";
        value = mkDevShell { inherit pkgs; llvmVersion = v; };
      }) llvmVersions));

      checks = forAllSystems ({ pkgs, system }:
        builtins.listToAttrs (map (v: {
          name = "cpp-llvm${toString v}";
          value = mkCppCheck { inherit pkgs; llvmVersion = v; };
        }) llvmVersions)
      );
    };
}
