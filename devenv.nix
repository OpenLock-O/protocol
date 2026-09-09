{ pkgs, ... }:

{
  scripts.nixd.exec = ''devenv lsp'';

  packages = with pkgs; [
    git
    pkg-config
    rustc
    cargo
    rustfmt
    clippy
    kotlin
    gradle
    jdk17
    cmake
    ninja
    swiftPackages.swift
    swiftPackages.swiftpm
  ];

  android = {
    enable = true;
    platforms.version = [ "35" ];
    buildTools.version = [ "35.0.0" ];
    cmake.version = [ "3.22.1" ];
    ndk.enable = true;
    sources.enable = false;
    systemImages.enable = false;
  };

  languages.rust.enable = true;
  languages.rust.channel = "stable";
  languages.rust.components = [ "rustc" "cargo" "rustfmt" "clippy" ];
  languages.rust.targets = [ "thumbv7em-none-eabihf" ];

  env.OPENLOCK_OFFLINE = "1";
  env.CARGO_NET_OFFLINE = "true";

  scripts.check.exec = ''
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
  '';

  scripts.unit-tests.exec = ''
    cargo test --workspace
  '';

  scripts.build.exec = ''
    cargo build --workspace --all-targets
  '';

  scripts.no-std-check.exec = ''
    set -eu
    cargo test --locked --workspace --no-default-features \
      --exclude openlock-issuer \
      --exclude openlock-ffi
    RUSTFLAGS='--cfg getrandom_backend="custom"' cargo check --locked --lib \
      -p openlock-types \
      -p openlock-crypto \
      -p openlock-protocol \
      -p openlock-core \
      -p openlock-transport \
      -p openlock-transport-ble \
      -p openlock-transport-nfc \
      --no-default-features \
      --target thumbv7em-none-eabihf
  '';

  enterShell = ''
    export RUST_BACKTRACE=1
    echo "OpenLock development environment"
    rustc --version
  '';
}
