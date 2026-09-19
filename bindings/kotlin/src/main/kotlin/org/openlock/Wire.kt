package org.openlock

internal sealed class Wire {
    data class UInt(val value: ULong) : Wire()
    data class Bytes(val value: ByteArray) : Wire()
    data class Text(val value: String) : Wire()
    data class Items(val value: List<Wire>) : Wire()
    data object Null : Wire()
    fun encode(): ByteArray {
        fun head(major: Int, n: ULong): ByteArray {
            if (n < 24u) return byteArrayOf(((major shl 5) or n.toInt()).toByte())
            val size = when { n <= 255u -> 1; n <= 65535u -> 2; n <= 0xffffffffu -> 4; else -> 8 }
            val ai = when (size) { 1 -> 24; 2 -> 25; 4 -> 26; else -> 27 }
            return byteArrayOf(((major shl 5) or ai).toByte()) + ByteArray(size) { (n shr ((size - 1 - it) * 8)).toByte() }
        }
        return when (this) {
            is UInt -> head(0, value)
            is Bytes -> head(2, value.size.toULong()) + value
            is Text -> value.toByteArray(Charsets.UTF_8).let { head(3, it.size.toULong()) + it }
            is Items -> value.fold(head(4, value.size.toULong())) { data, item -> data + item.encode() }
            Null -> byteArrayOf(0xf6.toByte())
        }
    }
    fun fields(size: Int): List<Wire> = (this as? Items)?.value?.also { require(it.size == size) } ?: error("Expected record")
    fun number(): ULong = (this as? UInt)?.value ?: error("Expected unsigned integer")
    fun bytes(): ByteArray = (this as? Bytes)?.value?.copyOf() ?: error("Expected bytes")
    fun text(): String = (this as? Text)?.value ?: error("Expected text")
    fun bool(): Boolean = number().also { require(it <= 1u) } == 1uL
    fun optional(): ULong? = if (this == Null) null else number()
    companion object {
        const val MAX_EVENT_SIZE = 4160
        fun decode(data: ByteArray, maxSize: Int = 4096): Wire {
            require(data.size <= maxSize); var offset = 0
            fun byte(): Int { require(offset < data.size); return data[offset++].toInt() and 255 }
            fun parse(depth: Int): Wire {
                require(depth < 32); val h = byte(); if (h == 0xf6) return Null
                val ai = h and 31
                var n = ai.toULong()
                if (ai >= 24) {
                    val count = when (ai) { 24 -> 1; 25 -> 2; 26 -> 4; 27 -> 8; else -> error("Unsupported CBOR") }
                    n = 0u; repeat(count) { n = (n shl 8) or byte().toULong() }
                }
                return when (h shr 5) {
                    0 -> UInt(n)
                    2, 3 -> { require(n <= (data.size - offset).toULong()); val value = data.copyOfRange(offset, offset + n.toInt()); offset += n.toInt(); if (h shr 5 == 2) Bytes(value) else Text(value.decodeToString(throwOnInvalidSequence = true)) }
                    4 -> { require(n <= 4096u); Items(List(n.toInt()) { parse(depth + 1) }) }
                    else -> error("Unsupported CBOR")
                }
            }
            val result = parse(0); require(offset == data.size && result.encode().contentEquals(data)); return result
        }
    }
}
internal fun u(n: ULong) = Wire.UInt(n)
internal fun b(value: ByteArray) = Wire.Bytes(value.copyOf())
internal fun arr(vararg value: Wire) = Wire.Items(value.toList())
sealed class Reading<out T> {
    data object Unsupported : Reading<Nothing>()
    data object Unknown : Reading<Nothing>()
    data class Known<T>(val value: T) : Reading<T>()
}
internal fun <T> reading(v: Wire, parse: (Wire) -> T): Reading<T> {
    val a = (v as Wire.Items).value
    return when (a.first().number()) {
        0uL -> { require(a.size == 1); Reading.Unsupported }
        1uL -> { require(a.size == 1); Reading.Unknown }
        2uL -> { require(a.size == 2); Reading.Known(parse(a[1])) }
        else -> error("Unknown reading")
    }
}
enum class BoltState { LOCKED, UNLOCKED }
enum class DoorState { CLOSED, OPEN }
enum class ActuatorKind { MOTOR, PULSE }
enum class OperationPhase { ACCEPTED, RUNNING, COMPLETED, FAILED, UNKNOWN }
enum class CompletionEvidence { NONE, DRIVER, SENSOR, NO_CHANGE }
enum class LockFault { NONE, JAMMED, TIMEOUT, SENSOR_CONFLICT, DRIVER, DOOR_AJAR }
enum class FirmwarePhase { EMPTY, RECEIVING, VERIFIED, TRIAL, CONFIRMED, FAILED }
internal inline fun <reified T : Enum<T>> enumeration(v: Wire): T { val n = v.number(); val values = enumValues<T>(); require(n < values.size.toULong()); return values[n.toInt()] }
class OperationStatus internal constructor(v: Wire) {
    private val f = v.fields(6)
    val credentialID = f[0].bytes(); val sequence = f[1].number(); val opcode = f[2].number()
    val phase = enumeration<OperationPhase>(f[3]); val evidence = enumeration<CompletionEvidence>(f[4]); val errorCode = f[5].number()
}
class LockStatus internal constructor(v: Wire) {
    private val f = v.fields(11)
    val bolt = reading(f[0]) { enumeration<BoltState>(it) }; val door = reading(f[1]) { enumeration<DoorState>(it) }
    val privacy = reading(f[2]) { it.bool() }; val batteryPercent = reading(f[3]) { it.number() }
    val fault = enumeration<LockFault>(f[4]); val active = if (f[5] == Wire.Null) null else OperationStatus(f[5])
    val epoch = f[6].number(); val policyVersion = f[7].number(); val configVersion = f[8].number(); val generation = f[9].number(); val clockTrusted = f[10].bool()
}
sealed class AutoRelock {
    data object Disabled : AutoRelock()
    data class Delay(val milliseconds: ULong) : AutoRelock()
    data class AfterClose(val milliseconds: ULong) : AutoRelock()
    internal fun wire() = when (this) { Disabled -> arr(u(0u)); is Delay -> arr(u(1u),u(milliseconds)); is AfterClose -> arr(u(2u),u(milliseconds)) }
    companion object { internal fun parse(v: Wire): AutoRelock { val a = (v as Wire.Items).value; return when (a.first().number()) { 0uL -> { require(a.size == 1); Disabled }; 1uL -> { require(a.size == 2); Delay(a[1].number()) }; 2uL -> { require(a.size == 2); AfterClose(a[1].number()) }; else -> error("Unknown relock mode") } } }
}
data class DeviceConfig(val version: ULong, val autoRelock: AutoRelock = AutoRelock.Disabled, val releaseMS: ULong = 500u, val actionTimeoutMS: ULong = 10000u, val holdOpen: Boolean = false, val doorAjarMS: ULong = 0u) {
    internal fun wire() = arr(u(version),autoRelock.wire(),u(releaseMS),u(actionTimeoutMS),u(if(holdOpen)1u else 0u),u(doorAjarMS))
    companion object { internal fun parse(v: Wire): DeviceConfig { val f = v.fields(6); return DeviceConfig(f[0].number(),AutoRelock.parse(f[1]),f[2].number(),f[3].number(),f[4].bool(),f[5].number()) } }
}
data class FirmwareManifest(val model: String, val hardware: String, val version: String, val size: ULong, val sha256: ByteArray, val securityVersion: ULong) {
    internal fun wire() = arr(Wire.Text(model),Wire.Text(hardware),Wire.Text(version),u(size),b(sha256),u(securityVersion))
    companion object { internal fun parse(v: Wire): FirmwareManifest { val f = v.fields(6); return FirmwareManifest(f[0].text(),f[1].text(),f[2].text(),f[3].number(),f[4].bytes(),f[5].number()) } }
}
class FirmwareStatus internal constructor(v: Wire) {
    private val f = v.fields(4); val phase = enumeration<FirmwarePhase>(f[0]); val received = f[1].number()
    val manifest = if (f[2] == Wire.Null) null else FirmwareManifest.parse(f[2]); val securityVersion = f[3].number()
}
class HardwareState internal constructor(v: Wire) {
    private val f = v.fields(4); val bolt = reading(f[0]) {enumeration<BoltState>(it)}; val door = reading(f[1]) {enumeration<DoorState>(it)}
    val privacy = reading(f[2]) {it.bool()}; val batteryPercent = reading(f[3]) {it.number()}
}
class AuditEvent internal constructor(v: Wire) {
    private val f = v.fields(8); val cursor = f[0].number(); val unixSeconds = f[1].optional(); val kind = f[2].number()
    val credentialID = if (f[3] == Wire.Null) null else f[3].bytes(); val sequence = f[4].optional(); val code = f[5].number()
    val hardware = if(f[6] == Wire.Null)null else HardwareState(f[6]); val operation = if(f[7] == Wire.Null)null else OperationStatus(f[7])
}
class AuditPage internal constructor(v: Wire) {
    private val f = v.fields(3); val events = (f[0] as Wire.Items).value.map { AuditEvent(it) }; val nextCursor = f[1].number(); val gap = f[2].bool()
}
class DeviceInfo internal constructor(v: Wire) {
    private val f = v.fields(20)
    val lockID = f[0].bytes(); val model = f[1].text(); val hardware = f[2].text(); val firmware = f[3].text(); val capabilities = f[4].number(); val actuator = enumeration<ActuatorKind>(f[5])
    val boltSensor = f[6].bool(); val doorSensor = f[7].bool(); val privacySensor = f[8].bool(); val batterySensor = f[9].bool(); val safeLockWithoutDoor = f[10].bool(); val holdOpen = f[11].bool()
    val maxReleaseMS = f[12].number(); val maxActionMS = f[13].number(); val maxDelayMS = f[14].number(); val logCapacity = f[15].number(); val operationCapacity = f[16].number(); val credentialCapacity = f[17].number(); val maxImageSize = f[18].number(); val maxChunkSize = f[19].number()
}
