package org.openlock

class OpenLockException(val code: Int) : RuntimeException("OpenLock error $code")
/** Thin byte-oriented wrapper; Android NFC/BLE callbacks remain platform code. */
class OpenLockSession private constructor(private var handle: Long) : AutoCloseable {
    companion object {
        init { System.loadLibrary("openlock_ffi") }
        @JvmStatic private external fun newInitiator(privateKey: ByteArray, lockPublic: ByteArray, capabilities: Long): Long
        @JvmStatic private external fun free(handle: Long)
        fun initiator(privateKey: ByteArray, lockPublic: ByteArray, capabilities: Long): OpenLockSession {
            require(privateKey.size == 32 && lockPublic.size == 32)
            val pointer = newInitiator(privateKey, lockPublic, capabilities); if (pointer == 0L) throw OpenLockException(-1); return OpenLockSession(pointer)
        }
    }
    override fun close() { if (handle != 0L) { free(handle); handle = 0L } }
}
