package org.openlock

class OpenLockException(val code: Int) : RuntimeException("OpenLock error $code")
internal object Native {
    init { System.loadLibrary("openlock_jni") }
    @JvmStatic external fun create(privateKey: ByteArray, publicKey: ByteArray, capabilities: Long): Long
    @JvmStatic external fun free(handle: Long)
    @JvmStatic external fun start(handle: Long): ByteArray
    @JvmStatic external fun send(handle: Long, command: ByteArray): ByteArray
    @JvmStatic external fun receive(handle: Long, packet: ByteArray): Array<ByteArray>
    @JvmStatic external fun publicKey(kind: Int, privateKey: ByteArray): ByteArray
    @JvmStatic external fun sign(kind: Int, privateKey: ByteArray, payload: ByteArray): ByteArray
}
class LockAction private constructor(internal val wire: Wire) {
    val opcode: ULong get() = (wire as Wire.Items).value.first().number()
    override fun toString() = "LockAction(opcode=$opcode)"
    companion object {
        private fun action(code: ULong, vararg fields: Wire) = LockAction(arr(u(code), *fields))
        internal fun parse(wire: Wire) = LockAction(wire)
        val Unlock = action(0u); val Status = action(1u); val Lock = action(3u); val Info = action(4u); val GetConfig = action(6u)
        val Reboot = action(10u); val FactoryReset = action(11u); val FirmwareFinish = action(15u); val FirmwareActivate = action(16u); val FirmwareAbort = action(17u); val FirmwareStatus = action(18u); val CredentialStatus = action(20u); val PairingStatus = action(22u)
        fun applyPolicy(signed: ByteArray) = action(2u,b(signed))
        fun operation(sequence: ULong) = action(5u,u(sequence))
        fun setConfig(config: DeviceConfig) = action(7u,config.wire())
        fun readLog(after: ULong, limit: ULong = 16u) = action(8u,u(after),u(limit))
        fun setClock(unixSeconds: ULong) = action(9u,u(unixSeconds))
        fun replaceIssuer(publicKey: ByteArray) = action(12u,b(publicKey))
        fun firmwareBegin(signed: ByteArray) = action(13u,b(signed))
        fun firmwareChunk(offset: ULong, data: ByteArray) = action(14u,u(offset),b(data))
        fun claim(setupKey: ByteArray, issuer: ByteArray, adminCredential: ByteArray) = action(19u,b(setupKey),b(issuer),b(adminCredential))
        fun rotateDeviceKey(signedUpdate: ByteArray) = action(21u,b(signedUpdate))
    }
}
sealed class LockReply {
    data class Operation(val value: OperationStatus) : LockReply()
    data class Status(val value: LockStatus) : LockReply()
    data class Info(val value: DeviceInfo) : LockReply()
    data class Config(val value: DeviceConfig) : LockReply()
    data class Audit(val value: AuditPage) : LockReply()
    data class Firmware(val value: FirmwareStatus) : LockReply()
    data class Claimed(val epoch: ULong, val generation: ULong) : LockReply()
    data class Credential(val uses: ULong, val maxUses: ULong?, val nextSequence: ULong) : LockReply()
    data class Pairing(val epoch: ULong, val generation: ULong, val windowOpen: Boolean) : LockReply()
    companion object {
        internal fun parse(v: Wire): LockReply { val f = v.fields(2); return when (f[0].number()) {
            0uL -> Operation(OperationStatus(f[1])); 1uL -> Status(LockStatus(f[1])); 2uL -> Info(DeviceInfo(f[1])); 3uL -> Config(DeviceConfig.parse(f[1])); 4uL -> Audit(AuditPage(f[1])); 5uL -> Firmware(FirmwareStatus(f[1]))
            6uL -> f[1].fields(2).let { Claimed(it[0].number(),it[1].number()) }
            7uL -> f[1].fields(3).let { Credential(it[0].number(),it[1].optional(),it[2].number()) }
            8uL -> f[1].fields(3).let { Pairing(it[0].number(),it[1].number(),it[2].bool()) }
            else -> error("Unknown reply")
        } }
    }
}
class LockResponse internal constructor(v: Wire) {
    private val f = v.fields(3); val opcode = f[0].number(); val errorCode = f[1].number(); val reply = if (errorCode == 0uL) LockReply.parse(f[2]) else null
}
sealed class SessionEvent {
    data class Handshake(val peer: ByteArray) : SessionEvent()
    data class Request(val id: ULong, val peer: ByteArray, val credential: ByteArray, val sequence: ULong?, val action: LockAction) : SessionEvent()
    data class Response(val id: ULong, val value: LockResponse) : SessionEvent()
    companion object {
        internal fun parse(data: ByteArray): SessionEvent { val f = Wire.decode(data).fields(4); return when (f[0].number()) {
            1uL -> Handshake(f[2].bytes())
            2uL -> f[3].fields(3).let { Request(f[1].number(),f[2].bytes(),it[0].bytes(),it[1].optional(),LockAction.parse(it[2])) }
            3uL -> Response(f[1].number(),LockResponse(f[3]))
            else -> error("Unknown event")
        } }
    }
}
/** Persist each credential's operation sequence independently of session handles. */
class OpenLockSession private constructor(private var handle: Long) : AutoCloseable {
    data class Sent(val requestID: ULong, val packet: ByteArray)
    data class Received(val event: SessionEvent?, val reply: ByteArray)
    companion object {
        fun initiator(privateKey: ByteArray, lockPublicKey: ByteArray, capabilities: ULong = 8_388_607u): OpenLockSession {
            require(privateKey.size == 32 && lockPublicKey.size == 32); return OpenLockSession(Native.create(privateKey,lockPublicKey,capabilities.toLong()))
        }
    }
    private fun live(): Long { check(handle != 0L); return handle }
    @Synchronized override fun close() { if (handle != 0L) { Native.free(handle); handle = 0L } }
    @Synchronized fun start() = Native.start(live())
    @Synchronized fun send(action: LockAction, credential: ByteArray = byteArrayOf(), sequence: ULong = 0u): Sent {
        val command = arr(b(credential),if(sequence == 0uL) Wire.Null else u(sequence),action.wire).encode()
        val data = Native.send(live(),command); require(data.size >= 4)
        var id = 0uL; for (i in 0..3) id = (id shl 8) or (data[i].toInt() and 255).toULong()
        return Sent(id,data.copyOfRange(4,data.size))
    }
    @Synchronized fun receive(packet: ByteArray): Received { val pair = Native.receive(live(),packet); return Received(if(pair[0].isEmpty())null else SessionEvent.parse(pair[0]),pair[1]) }
}
class SetupPayload(qrText: String) {
    val lockID: ByteArray; val publicKey: ByteArray; val setupKey: ByteArray
    init { val parts = qrText.split(':'); require(parts.size == 4 && parts[0] == "OPENLOCK4")
        fun hex(s: String, count: Int): ByteArray { require(s.length == count*2 && s.all { it in '0'..'9' || it in 'a'..'f' }); return ByteArray(count) { s.substring(it*2,it*2+2).toInt(16).toByte() } }
        lockID = hex(parts[1],16); publicKey = hex(parts[2],32); setupKey = hex(parts[3],32); require(setupKey.any { it != 0.toByte() })
    }
    override fun toString() = "SetupPayload(<redacted>)"
}
object OpenLockIssuer {
    const val ALL_RIGHTS: ULong = 2047u
    fun publicKey(privateKey: ByteArray, signing: Boolean = true): ByteArray { require(privateKey.size == 32); return Native.publicKey(if(signing)1 else 0,privateKey) }
    fun issue(privateKey: ByteArray, credentialID: ByteArray, lockID: ByteArray, subjectKey: ByteArray, rights: ULong, epoch: ULong, validity: Pair<ULong,ULong>? = null, maxUses: ULong? = null): ByteArray {
        require(privateKey.size == 32)
        return Native.sign(0,privateKey,arr(u(2u),Wire.Text("grant"),b(credentialID),b(lockID),b(subjectKey),u(rights),u(epoch),validity?.let { arr(u(it.first),u(it.second)) } ?: Wire.Null,maxUses?.let(::u) ?: Wire.Null).encode())
    }
    fun revoke(privateKey: ByteArray, lockID: ByteArray, epoch: ULong, version: ULong, credentials: List<ByteArray>): ByteArray {
        val sorted = credentials.map { it.joinToString("") { byte -> "%02x".format(byte.toInt() and 255) } }.distinct().sorted().map { text -> ByteArray(text.length/2) { text.substring(it*2,it*2+2).toInt(16).toByte() } }
        return Native.sign(1,privateKey,arr(u(2u),Wire.Text("policy"),b(lockID),u(epoch),u(version),Wire.Items(sorted.map(::b))).encode())
    }
    fun signFirmware(privateKey: ByteArray, manifest: FirmwareManifest) = Native.sign(2,privateKey,manifest.wire().encode())
}

data class DeviceKeyDescriptor(val deviceID: ByteArray, val keyID: ULong, val keyVersion: ULong, val publicKey: ByteArray, val rotationPublicKey: ByteArray, val capabilities: ULong = 8_388_607u) {
    internal fun payload(issuerKeyID: ULong) = arr(u(2u),b(deviceID),u(keyID),u(keyVersion),b(publicKey),b(rotationPublicKey),u(capabilities),u(issuerKeyID))
}
data class SignedDeviceKey(val key: DeviceKeyDescriptor,val issuerKeyID: ULong,val signature: ByteArray)
fun OpenLockIssuer.signDeviceKey(privateKey: ByteArray,key: DeviceKeyDescriptor,issuerKeyID: ULong): SignedDeviceKey = SignedDeviceKey(key,issuerKeyID,Native.sign(3,privateKey,key.payload(issuerKeyID).encode()))
fun OpenLockIssuer.signRotation(privateKey: ByteArray,oldKeyID: ULong,newRecord: SignedDeviceKey,notBefore: ULong,retireAfter: ULong,issuerKeyID: ULong?): ByteArray {
    val payload = arr(u(2u),u(oldKeyID),newRecord.key.payload(newRecord.issuerKeyID),u(notBefore),u(retireAfter),issuerKeyID?.let(::u) ?: Wire.Null)
    val signature = Native.sign(4,privateKey,payload.encode())
    return arr(b(signature),b(newRecord.signature)).encode()
}
