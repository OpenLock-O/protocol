package org.openlock


/** Plaintext, unauthenticated result; it is not proof of physical opening. */
data class OpenLockResponse(val credentialId: Long, val timeStep: Long, val errorCode: Int)

/** OpenLock TOTP client. Applications own BLE/NFC I/O and key storage. */
object OpenLock {
    init { System.loadLibrary("openlock_jni") }

    @JvmStatic private external fun makeUnlockNative(secret: ByteArray, credentialId: Long, unixSeconds: Long): ByteArray
    @JvmStatic private external fun encodeUnlockNative(credentialId: Long, timeStep: Long, code: Int): ByteArray
    @JvmStatic private external fun decodeResponseNative(input: ByteArray): LongArray

    fun makeUnlock(secret: ByteArray, credentialId: Long, unixSeconds: Long): ByteArray {
        require(secret.size == 32 && credentialId in 1..0xffff_ffffL && unixSeconds >= 0)
        return makeUnlockNative(secret, credentialId, unixSeconds)
    }

    fun encodeUnlock(credentialId: Long, timeStep: Long, code: Int): ByteArray {
        require(credentialId in 1..0xffff_ffffL && timeStep >= 0 && code in 0..99_999_999)
        return encodeUnlockNative(credentialId, timeStep, code)
    }

    fun decodeResponse(input: ByteArray): OpenLockResponse {
        require(input.size == 15)
        val fields = decodeResponseNative(input)
        return OpenLockResponse(fields[0], fields[1], fields[2].toInt())
    }
}
