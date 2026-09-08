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
  ];

  languages.rust.enable = true;
  languages.rust.channel = "stable";
  languages.rust.components = [ "rustc" "cargo" "rustfmt" "clippy" ];

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

  enterShell = ''
    export RUST_BACKTRACE=1
    echo "OpenLock development environment"
    rustc --version
  '';
}
