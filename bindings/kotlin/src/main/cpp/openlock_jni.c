#include <jni.h>
#include <stdint.h>
#include "openlock.h"

static void throw_code(JNIEnv *env, int32_t code) {
    jclass type = (*env)->FindClass(env, "org/openlock/OpenLockException");
    if (!type) return;
    jmethodID ctor = (*env)->GetMethodID(env, type, "<init>", "(I)V");
    if (ctor) {
        jobject exception = (*env)->NewObject(env, type, ctor, (jint)code);
        if (exception) {
            (*env)->Throw(env, (jthrowable)exception);
            (*env)->DeleteLocalRef(env, exception);
        }
    }
    (*env)->DeleteLocalRef(env, type);
}

static jbyteArray return_bytes(JNIEnv *env, const uint8_t *bytes, size_t len, int32_t code) {
    if (code != 0) { throw_code(env, code); return NULL; }
    jbyteArray result = (*env)->NewByteArray(env, (jsize)len);
    if (result) (*env)->SetByteArrayRegion(env, result, 0, (jsize)len, (const jbyte *)bytes);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openlock_OpenLock_makeUnlockNative(
    JNIEnv *env, jclass klass, jbyteArray secret, jlong credential_id, jlong unix_seconds) {
    (void)klass;
    if (!secret || (*env)->GetArrayLength(env, secret) != OPENLOCK_SECRET_SIZE ||
        credential_id <= 0 || (uint64_t)credential_id > UINT32_MAX || unix_seconds < 0) {
        throw_code(env, 3); return NULL;
    }
    uint8_t key[OPENLOCK_SECRET_SIZE] = {0};
    (*env)->GetByteArrayRegion(env, secret, 0, OPENLOCK_SECRET_SIZE, (jbyte *)key);
    if ((*env)->ExceptionCheck(env)) return NULL;
    uint8_t bytes[OPENLOCK_REQUEST_SIZE];
    size_t len = 0;
    int32_t code = openlock_make_unlock(key, (uint32_t)credential_id, (uint64_t)unix_seconds,
                                       bytes, sizeof(bytes), &len);
    /* Erase the temporary native key copy, including on an ABI error. */
    volatile uint8_t *wipe = key;
    for (size_t i = 0; i < sizeof(key); ++i) wipe[i] = 0;
    return return_bytes(env, bytes, len, code);
}

JNIEXPORT jbyteArray JNICALL Java_org_openlock_OpenLock_encodeUnlockNative(
    JNIEnv *env, jclass klass, jlong credential_id, jlong time_step, jint otp) {
    (void)klass;
    if (credential_id <= 0 || (uint64_t)credential_id > UINT32_MAX || time_step < 0 || otp < 0) {
        throw_code(env, 3); return NULL;
    }
    uint8_t bytes[OPENLOCK_REQUEST_SIZE];
    size_t len = 0;
    int32_t code = openlock_encode_unlock((uint32_t)credential_id, (uint64_t)time_step,
                                         (uint32_t)otp, bytes, sizeof(bytes), &len);
    return return_bytes(env, bytes, len, code);
}

JNIEXPORT jlongArray JNICALL Java_org_openlock_OpenLock_decodeResponseNative(
    JNIEnv *env, jclass klass, jbyteArray input) {
    (void)klass;
    if (!input || (*env)->GetArrayLength(env, input) != OPENLOCK_RESPONSE_SIZE) {
        throw_code(env, 3); return NULL;
    }
    uint8_t bytes[OPENLOCK_RESPONSE_SIZE];
    (*env)->GetByteArrayRegion(env, input, 0, OPENLOCK_RESPONSE_SIZE, (jbyte *)bytes);
    if ((*env)->ExceptionCheck(env)) return NULL;
    openlock_response_t response;
    int32_t code = openlock_decode_response(bytes, sizeof(bytes), &response);
    if (code != 0) { throw_code(env, code); return NULL; }
    if (response.time_step > INT64_MAX) { throw_code(env, 3); return NULL; }
    const jlong fields[] = { (jlong)response.credential_id, (jlong)response.time_step,
                            (jlong)response.error_code };
    jlongArray result = (*env)->NewLongArray(env, 3);
    if (result) (*env)->SetLongArrayRegion(env, result, 0, 3, fields);
    return result;
}
