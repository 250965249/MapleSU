#include "block_partition_ioctl.h"
#include <jni.h>
#include <sys/ioctl.h>

extern "C" JNIEXPORT jint JNICALL
Java_dev_maplesu_manager_installer_BlockPartitionControl_readOnly(JNIEnv*, jobject, jint descriptor, jint desired) {
    return maplesu::block_partition_read_only(descriptor, desired,
        [](int fd, unsigned long operation, int* value) { return ioctl(fd, operation, value); });
}
