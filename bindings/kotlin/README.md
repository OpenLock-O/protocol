# Kotlin binding

The Kotlin class is a small JVM/Android wrapper around the v2 C ABI. Build the
Rust `openlock-ffi` shared library for the Android ABI, configure it as the
`openlock_ffi` dependency in the Android native build, and build the JNI shim in
`src/main/cpp`. Android BLE and NFC callbacks remain application code; this
binding only owns session handles and byte buffers.
