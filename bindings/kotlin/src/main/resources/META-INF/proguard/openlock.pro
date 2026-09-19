# JNI exports use these binary names and native method names.
-keep class org.openlock.Native {
    *;
}

# openlock_jni.c constructs this exception through FindClass/GetMethodID.
-keep class org.openlock.OpenLockException {
    public <init>(int);
}
