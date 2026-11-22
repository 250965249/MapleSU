#include <android/log.h>
#include <jni.h>

#define TAG "T2HostNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("libt2host JNI_OnLoad v=%d", JNI_VERSION_1_6);
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jstring JNICALL
Java_dev_maplesu_t2host_MainActivity_nativeMarker(JNIEnv* env, jclass clazz) {
    LOGI("libt2host nativeMarker called");
    return env->NewStringUTF("t2host-native-ok");
}
