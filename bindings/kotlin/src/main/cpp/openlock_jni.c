#include <jni.h>
#include <stdint.h>
#include <string.h>
#include "openlock.h"

static void fail(JNIEnv *env, int32_t code) {
    jclass type = (*env)->FindClass(env, "org/openlock/OpenLockException");
    if (!type) return;
    jmethodID init = (*env)->GetMethodID(env,type,"<init>","(I)V");
    if (!init) return;
    jobject error = (*env)->NewObject(env,type,init,(jint)code);
    if (error) (*env)->Throw(env,(jthrowable)error);
}
static int read(JNIEnv *env,jbyteArray input,uint8_t *out,size_t capacity,jsize *length) {
    if (!input) { fail(env,-1); return 0; }
    *length=(*env)->GetArrayLength(env,input);
    if ((size_t)*length>capacity) { fail(env,1); return 0; }
    (*env)->GetByteArrayRegion(env,input,0,*length,(jbyte*)out);
    return !(*env)->ExceptionCheck(env);
}
static jbyteArray result(JNIEnv *env,int32_t code,const uint8_t *data,size_t length) {
    if (code) {fail(env,code);return NULL;}
    jbyteArray out=(*env)->NewByteArray(env,(jsize)length);
    if (out && length) (*env)->SetByteArrayRegion(env,out,0,(jsize)length,(const jbyte*)data);
    return out;
}
static openlock_session_t *session(JNIEnv *env,jlong handle) {
    if (!handle) {fail(env,17);return NULL;}
    return (openlock_session_t*)(intptr_t)handle;
}
JNIEXPORT jlong JNICALL Java_org_openlock_Native_create(JNIEnv *env,jclass type,jbyteArray private_key,jbyteArray public_key,jlong capabilities) {
    (void)type; uint8_t private_bytes[32],public_bytes[32]; jsize pn,qn;
    if (!read(env,private_key,private_bytes,32,&pn)||!read(env,public_key,public_bytes,32,&qn)) return 0;
    if (pn!=32||qn!=32){fail(env,-1);return 0;}
    openlock_session_t *out=NULL;
    int32_t code=openlock_session_initiator(private_bytes,public_bytes,(uint64_t)capabilities,&out);
    volatile uint8_t *wipe=private_bytes;for(size_t i=0;i<32;i++)wipe[i]=0;
    if(code){fail(env,code);return 0;}return (jlong)(intptr_t)out;
}
JNIEXPORT void JNICALL Java_org_openlock_Native_free(JNIEnv *env,jclass type,jlong handle){(void)env;(void)type;openlock_session_free((openlock_session_t*)(intptr_t)handle);}
JNIEXPORT jbyteArray JNICALL Java_org_openlock_Native_start(JNIEnv *env,jclass type,jlong handle){
    (void)type;openlock_session_t *s=session(env,handle);if(!s)return NULL;
    uint8_t out[4096];size_t length=0;int32_t code=openlock_session_start(s,out,sizeof out,&length);return result(env,code,out,length);
}
JNIEXPORT jbyteArray JNICALL Java_org_openlock_Native_send(JNIEnv *env,jclass type,jlong handle,jbyteArray command){
    (void)type;openlock_session_t *s=session(env,handle);if(!s)return NULL;
    uint8_t input[4096],out[4100];jsize count;size_t length=0;uint32_t id=0;
    if(!read(env,command,input,sizeof input,&count))return NULL;
    int32_t code=openlock_session_send(s,input,(size_t)count,&id,out+4,4096,&length);
    out[0]=(uint8_t)(id>>24);out[1]=(uint8_t)(id>>16);out[2]=(uint8_t)(id>>8);out[3]=(uint8_t)id;
    return result(env,code,out,length+4);
}
JNIEXPORT jobjectArray JNICALL Java_org_openlock_Native_receive(JNIEnv *env,jclass type,jlong handle,jbyteArray packet){
    (void)type;openlock_session_t *s=session(env,handle);if(!s)return NULL;
    uint8_t input[OPENLOCK_MAX_MESSAGE_SIZE],event[OPENLOCK_MAX_EVENT_SIZE],reply[OPENLOCK_MAX_MESSAGE_SIZE];jsize count;size_t event_len=0,reply_len=0;
    if(!read(env,packet,input,sizeof input,&count))return NULL;
    int32_t code=openlock_session_receive(s,input,(size_t)count);
    if(!code)code=openlock_session_take_event(s,event,sizeof event,&event_len);
    if(!code)code=openlock_session_take_output(s,reply,sizeof reply,&reply_len);
    if(code){fail(env,code);return NULL;}
    jclass bytes=(*env)->FindClass(env,"[B");if(!bytes)return NULL;
    jobjectArray out=(*env)->NewObjectArray(env,2,bytes,NULL);if(!out)return NULL;
    jbyteArray a=result(env,0,event,event_len),b=result(env,0,reply,reply_len);
    if(a&&b){(*env)->SetObjectArrayElement(env,out,0,a);(*env)->SetObjectArrayElement(env,out,1,b);}return out;
}
JNIEXPORT jbyteArray JNICALL Java_org_openlock_Native_publicKey(JNIEnv *env,jclass type,jint kind,jbyteArray key){
    (void)type;uint8_t private_bytes[32],out[32];jsize count;
    if(!read(env,key,private_bytes,32,&count))return NULL;if(count!=32){fail(env,-1);return NULL;}
    int32_t code=openlock_public_key((uint32_t)kind,private_bytes,out);
    volatile uint8_t *wipe=private_bytes;for(size_t i=0;i<32;i++)wipe[i]=0;
    return result(env,code,out,32);
}
JNIEXPORT jbyteArray JNICALL Java_org_openlock_Native_sign(JNIEnv *env,jclass type,jint kind,jbyteArray key,jbyteArray payload){
    (void)type;uint8_t private_bytes[32],input[4096],out[4096];jsize count,private_len;size_t length=0;
    if(!read(env,key,private_bytes,32,&private_len)||!read(env,payload,input,sizeof input,&count))return NULL;
    if(private_len!=32){fail(env,-1);return NULL;}
    int32_t code=openlock_sign((uint32_t)kind,private_bytes,input,(size_t)count,out,sizeof out,&length);
    volatile uint8_t *wipe=private_bytes;for(size_t i=0;i<32;i++)wipe[i]=0;
    return result(env,code,out,length);
}
