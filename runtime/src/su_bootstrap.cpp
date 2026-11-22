#include "su_protocol.h"
#include <jni.h>
#include <cstdio>

extern "C" JNIEXPORT void JNICALL
Java_dev_maplesu_manager_runtime_NativeSuBootstrap_sendTerminal(JNIEnv* environment, jclass, jint control, jint terminal) {
    const int descriptor = terminal;
    if (control >= 0 && terminal >= 0 && maplesu::send_fds(control, 'P', &descriptor, 1)) return;
    environment->ThrowNew(environment->FindClass("java/io/IOException"), "SU_TERMINAL_TRANSFER_FAILED");
}
