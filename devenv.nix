{ lib, pkgs, ... }:

{
  scripts.nixd.exec = ''devenv lsp'';

  packages = with pkgs; [
    git
    glab
    go-task
    python3
  ] ++ lib.optionals stdenv.isLinux [
    awscli2
    curl
    docker-buildx
    docker-client
    docker-compose
    jq
    openssh
  ] ++ lib.optionals stdenv.isDarwin [
    cocoapods
    xcodegen
  ];

  apple.sdk = null;

  # Keep Xcode's complete Apple toolchain instead of Nix's generic drivers.
  unsetEnvVars = lib.mkOptionDefault (
    lib.optionals pkgs.stdenv.isDarwin [ "AR" "CC" "CXX" "LD" ]
  );

  enterTest = lib.optionalString pkgs.stdenv.isDarwin ''
    test -z "''${AR-}"
    test -z "''${CC-}"
    test -z "''${CXX-}"
    test -z "''${LD-}"
    test -x "$(/usr/bin/xcrun --find clang)"
    test -x "$(/usr/bin/xcrun --find ld)"
  '';

  languages.javascript = {
    enable = true;
    package = pkgs.nodejs-slim_24;
    corepack.enable = true;
    npm.enable = true;
  };
}
