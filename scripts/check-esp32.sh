#!/usr/bin/env bash
# Build runtime libraries with std for ESP-IDF; no board or SDK link is required.
set -euo pipefail
cd "$(dirname "$0")/.."

targets=(
    xtensa-esp32-espidf
    xtensa-esp32s2-espidf
    xtensa-esp32s3-espidf
    riscv32imc-esp-espidf
    riscv32imac-esp-espidf
)
if [[ $# -gt 0 ]]; then
    targets=("$@")
fi

# Validate the entire selection before starting any builds.
for target in "${targets[@]}"; do
    case "$target" in
        xtensa-esp32-espidf|xtensa-esp32s2-espidf|xtensa-esp32s3-espidf|riscv32imc-esp-espidf|riscv32imac-esp-espidf) ;;
        *)
            echo "Unsupported ESP-IDF target: $target" >&2
            exit 2
            ;;
    esac
done

if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup is required; see docs/architecture.md#esp32-with-esp-idf-and-std" >&2
    exit 1
fi

for target in "${targets[@]}"; do
    case "$target" in
        xtensa-*) toolchain="${ESP_XTENSA_TOOLCHAIN:-esp}" ;;
        riscv32*) toolchain="${ESP_RISCV_TOOLCHAIN:-nightly}" ;;
    esac
    # Devenv's stable rustc can precede rustup's proxies on PATH. Pair Cargo
    # with this toolchain's compiler and rust-src, including inside Devenv.
    rustc_path="$(rustup which --toolchain "$toolchain" rustc)"
    # Keep default features enabled: every selected runtime crate uses std.
    RUSTC="$rustc_path" rustup run "$toolchain" cargo build --locked --release --lib \
        -Zbuild-std=std,panic_abort \
        -p openlock-types \
        -p openlock-crypto \
        -p openlock-protocol \
        -p openlock-core \
        -p openlock-transport \
        -p openlock-transport-ble \
        -p openlock-transport-nfc \
        --target "$target"
done
