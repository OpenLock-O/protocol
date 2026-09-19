package org.openlock
import java.security.MessageDigest

fun main() {
    val path = requireNotNull(System.getenv("OPENLOCK_SIMULATOR"))
    val process = ProcessBuilder(path).start()
    try {
        val writer = process.outputStream.bufferedWriter(); val reader = process.inputStream.bufferedReader()
        fun line(value: String): String {writer.write(value);writer.newLine();writer.flush();val result = reader.readLine() ?: error("Simulator exited");check(!result.startsWith("error:")) {result};return result}
        fun exchange(packet: ByteArray): ByteArray {val text = line(packet.joinToString("") {"%02x".format(it.toInt() and 255)});return ByteArray(text.length/2) {text.substring(it*2,it*2+2).toInt(16).toByte()}}
        val holder = ByteArray(32) {3};val issuer = ByteArray(32) {9};val lockID = ByteArray(16) {1}
        var public = OpenLockIssuer.publicKey(ByteArray(32) {4},false)
        fun connect(): OpenLockSession {check(line("connect") == "ok");val s = OpenLockSession.initiator(holder,public);check(s.receive(exchange(s.start())).event is SessionEvent.Handshake);return s}
        var session = connect()
        val grant = OpenLockIssuer.issue(issuer,ByteArray(16) {2},lockID,OpenLockIssuer.publicKey(holder,false),2047u,0u)
        fun request(action: LockAction,seq: ULong = 0u,credential: ByteArray = grant): LockReply {
            val sent = session.send(action,credential,seq);val received = session.receive(exchange(sent.packet)).event as SessionEvent.Response
            check(received.id == sent.requestID);check(received.value.errorCode == 0uL) {"Protocol error ${received.value.errorCode}"}
            return requireNotNull(received.value.reply)
        }
        check((request(LockAction.PairingStatus,credential = byteArrayOf()) as LockReply.Pairing).windowOpen)
        request(LockAction.claim(ByteArray(32) {7},OpenLockIssuer.publicKey(issuer),grant),1u,byteArrayOf());session.close();session = connect()
        check((request(LockAction.Unlock,1u) as LockReply.Operation).value.phase == OperationPhase.RUNNING);check(line("complete-unlock") == "ok")
        check((request(LockAction.Status) as LockReply.Status).value.bolt == Reading.Known(BoltState.UNLOCKED))
        request(LockAction.Lock,2u);check(line("complete-lock") == "ok")
        request(LockAction.setConfig(DeviceConfig(1u)),3u);check((request(LockAction.GetConfig) as LockReply.Config).value.version == 1uL)
        check((request(LockAction.readLog(0u)) as LockReply.Audit).value.events.isNotEmpty())
        val image = "abc".toByteArray();val manifest = FirmwareManifest("reference-lock","rev-a","2.0",3u,MessageDigest.getInstance("SHA-256").digest(image),1u)
        val signed = OpenLockIssuer.signFirmware(ByteArray(32) {8},manifest)
        request(LockAction.firmwareBegin(signed),4u);request(LockAction.firmwareChunk(0u,image),5u);request(LockAction.FirmwareFinish,6u);request(LockAction.FirmwareActivate,7u);check(line("confirm-boot") == "ok")
        check((request(LockAction.FirmwareStatus) as LockReply.Firmware).value.phase == FirmwarePhase.CONFIRMED)
        val policy = OpenLockIssuer.revoke(issuer,lockID,0u,1u,listOf(ByteArray(16) {5}));request(LockAction.applyPolicy(policy),8u)
        request(LockAction.setClock(2000u),9u);request(LockAction.Reboot,10u)
        val newPublic = OpenLockIssuer.publicKey(ByteArray(32) {12},false)
        val descriptor = DeviceKeyDescriptor(lockID,2u,2u,newPublic,OpenLockIssuer.publicKey(ByteArray(32) {13}))
        val record = OpenLockIssuer.signDeviceKey(issuer,descriptor,1u)
        val rotation = OpenLockIssuer.signRotation(issuer,1u,record,1900u,2100u,1u)
        request(LockAction.rotateDeviceKey(rotation),11u);session.close();public = newPublic;session = connect()
        check(line("confirm-next") == "ok");request(LockAction.FactoryReset,12u);session.close();public = OpenLockIssuer.publicKey(ByteArray(32) {4},false);session = connect()
        check((request(LockAction.PairingStatus,credential = byteArrayOf()) as LockReply.Pairing).epoch == 1uL);session.close()
        println("Kotlin/JNI device lifecycle passed")
    } finally {process.destroy();process.waitFor()}
}
