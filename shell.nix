{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  packages = with pkgs; [
    clang
    llvm_18
    cmake
    ninja
    pkg-config

    zlib
    zstd
    llvm_18.dev
    llvm_18.lib

  ];

  shellHook = ''
    export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath [pkgs.llvm_18 pkgs.zlib pkgs.zstd]}:$LD_LIBRARY_PATH
  '';
}
