#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cmp include/openlock.h bindings/swift/Sources/OpenLockFFI/openlock.h
cmp include/module.modulemap bindings/swift/Sources/OpenLockFFI/module.modulemap
export OPENLOCK_SIMULATOR="$PWD/target/debug/examples/simulator"
export OPENLOCK_LIBRARY_DIR="$PWD/target/debug"
export LIBRARY_PATH="$OPENLOCK_LIBRARY_DIR${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$OPENLOCK_LIBRARY_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export DYLD_LIBRARY_PATH="$OPENLOCK_LIBRARY_DIR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
cargo build --locked -p openlock-ffi
cargo build --locked -p openlock-core --example simulator
"$OPENLOCK_SIMULATOR" fixtures > target/abi-fixtures.txt
cc -Wall -Wextra -Werror -Iinclude crates/openlock-ffi/tests/lifecycle.c -Ltarget/debug -lopenlock_ffi -Wl,-rpath,"$OPENLOCK_LIBRARY_DIR" -o target/c-lifecycle
target/c-lifecycle target/abi-fixtures.txt
cmake -S bindings/kotlin/src/main/cpp -B bindings/kotlin/build/native
cmake --build bindings/kotlin/build/native
(
    cd bindings/kotlin
    gradle --no-daemon --console=plain build integrationTest
)
(
    cd bindings/swift
    swift run -Xlinker -L"$OPENLOCK_LIBRARY_DIR" -Xlinker -rpath -Xlinker "$OPENLOCK_LIBRARY_DIR" OpenLockIntegration
)
