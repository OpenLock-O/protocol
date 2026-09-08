#include <jni.h>
#include <stdint.h>
#include "openlock.h"

JNIEXPORT jlong JNICALL Java_org_openlock_OpenLockSession_newInitiator(
    JNIEnv *env, jclass klass, jbyteArray private_key, jbyteArray lock_public,
    jlong capabilities) {
    (void)klass;
    if (!private_key || !lock_public || (*env)->GetArrayLength(env, private_key) != 32 ||
        (*env)->GetArrayLength(env, lock_public) != 32) return 0;
    jbyte *private_bytes = (*env)->GetByteArrayElements(env, private_key, 0);
    jbyte *public_bytes = (*env)->GetByteArrayElements(env, lock_public, 0);
    openlock_session_t *session = NULL;
    int32_t code = openlock_session_initiator((const uint8_t *)private_bytes,
        (const uint8_t *)public_bytes, (uint64_t)capabilities, &session);
    (*env)->ReleaseByteArrayElements(env, private_key, private_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, lock_public, public_bytes, JNI_ABORT);
    return code == 0 ? (jlong)(intptr_t)session : 0;
}

JNIEXPORT void JNICALL Java_org_openlock_OpenLockSession_free(
    JNIEnv *env, jclass klass, jlong handle) {
    (void)env; (void)klass;
    openlock_session_free((openlock_session_t *)(intptr_t)handle);
}
