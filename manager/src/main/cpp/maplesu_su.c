/*
 * MapleSU L3 su client -- user-space half of the kernel gate (ABI v2, 2026-10-31).
 *
 * ABI v2 (identical on all three lanes: helper ARM, module, manager SU):
 *   prctl(PR_SET_DUMPABLE (4), op, token_lo, token_hi, arg5)
 *     op=0  ARM : the helper's leg. Requires selinux enforcing == 0 (the open
 *                 window), caller uid == 0, owner_uid = arg5 in [10000,100000),
 *                 token != 0 and CAS 0->1 on the armed flag.
 *     op=1  SU  : requires ARMED, caller uid == owner_uid and a matching token;
 *                 commits one pre-allocated kernel root cred to the current task.
 *     no token   : forwarded unchanged to the saved original __arm64_sys_prctl.
 *
 * The gate is recognised by the argument pattern, not by a private option number:
 * option == PR_SET_DUMPABLE && (token_lo | token_hi) != 0. A zero token is never
 * magic, so an ordinary prctl(PR_SET_DUMPABLE, 0|1, 0, 0, 0) keeps its native
 * meaning - and so does this client's op=1 call, which returns 0 exactly as
 * PR_SET_DUMPABLE does. argv[3] (owner_uid) is not used by the SU branch.
 *
 * This file only ever issues op=1, and only from a freshly forked child. The
 * process that called in (an ART process) never changes its own credentials: the
 * child proves getuid()==0 and geteuid()==0 after the prctl and then execs the
 * caller's argv. If either step fails it exits 126 (gate denied) or 127 (exec
 * returned) instead of pretending to have run anything.
 *
 * The child performs no allocation and no stdio between fork() and execv():
 * everything it needs was built in the parent, and its two error paths write a
 * fixed stack buffer. The parent drains both pipes with a deadline, kills the
 * child on timeout and reaps it; nothing is left running either way.
 *
 * argv strings are converted with GetStringUTFChars (modified UTF-8). A script
 * containing U+0000 cannot be represented as a C string and is rejected by the
 * JVM conversion rather than silently truncated.
 */
#define _GNU_SOURCE

#include <jni.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
 * ABI v2 dropped the private option number. The call is the gate only when
 * option == PR_SET_DUMPABLE *and* a non-zero token is in arg3/arg4, so using the
 * kernel's own constant is the whole magic: PR_SET_DUMPABLE (4) is a real option,
 * and the "no token" form is forwarded to __arm64_sys_prctl like any other call.
 * A stale v1 number would be an unknown option and earn EINVAL instead of a cred.
 */
#define MSU_ABI_VERSION 2
#define MSU_PRCTL_OPTION PR_SET_DUMPABLE

/* ABI v2 operations, carried in arg2. This client only ever issues MSU_OP_SU. */
#define MSU_OP_ARM 0
#define MSU_OP_SU 1

/* Exit codes the Kotlin side also names (NativeSu.EXIT_*). */
#define MSU_EXIT_GATE_DENIED 126
#define MSU_EXIT_EXEC_FAILED 127
#define MSU_EXIT_TIMEOUT 124

#define MSU_DEFAULT_TIMEOUT_MS 30000
#define MSU_BUFFER_LIMIT (256u * 1024u)

/* Parent-only: no fork may inherit a transient writer that is not in the
 * streaming table. Hold through pipe creation, fork, and parent close/store;
 * also through a table take and its final write/close. Children never use this
 * mutex, and no output, authorization or waitpid wait is performed under it.
 * Lock order, when nested: msu_fds_lock -> msu_streams_lock. */
static pthread_mutex_t msu_fds_lock = PTHREAD_MUTEX_INITIALIZER;

struct msu_buffer {
    char *data;
    size_t length;
    size_t capacity;
    int truncated;
};

static int64_t msu_now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (int64_t)now.tv_sec * 1000 + (int64_t)(now.tv_nsec / 1000000);
}

/* --- async-signal-safe formatting for the child's error lines ------------- */

static void msu_put_text(char *out, size_t *at, size_t capacity, const char *text) {
    while (*text != '\0' && *at + 1 < capacity) out[(*at)++] = *text++;
}

static void msu_put_signed(char *out, size_t *at, size_t capacity, long value) {
    char digits[24];
    size_t count = 0;
    unsigned long magnitude;
    if (value < 0) {
        if (*at + 1 < capacity) out[(*at)++] = '-';
        magnitude = (unsigned long)(-(value + 1)) + 1UL;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[count++] = (char)('0' + (magnitude % 10UL));
        magnitude /= 10UL;
    } while (magnitude != 0UL && count < sizeof(digits));
    while (count > 0 && *at + 1 < capacity) out[(*at)++] = digits[--count];
}

static void msu_put_unsigned(char *out, size_t *at, size_t capacity, unsigned long value) {
    char digits[24];
    size_t count = 0;
    do {
        digits[count++] = (char)('0' + (value % 10UL));
        value /= 10UL;
    } while (value != 0UL && count < sizeof(digits));
    while (count > 0 && *at + 1 < capacity) out[(*at)++] = digits[--count];
}

/* --- parent-side buffers -------------------------------------------------- */

static int msu_append(struct msu_buffer *buffer, const char *data, size_t length) {
    size_t room;
    char *grown;
    size_t capacity;
    if (length == 0) return 0;
    if (buffer->length >= MSU_BUFFER_LIMIT) {
        buffer->truncated = 1;
        return 0;
    }
    room = MSU_BUFFER_LIMIT - buffer->length;
    if (length > room) {
        length = room;
        buffer->truncated = 1;
    }
    if (buffer->length + length > buffer->capacity) {
        capacity = buffer->capacity != 0 ? buffer->capacity : 4096u;
        while (capacity < buffer->length + length) capacity *= 2u;
        grown = (char *)realloc(buffer->data, capacity);
        if (grown == NULL) return -1;
        buffer->data = grown;
        buffer->capacity = capacity;
    }
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    return 0;
}

/*
 * 1 = EOF, 0 = would block, -1 = read error. The caller always keeps draining so a
 * chatty child can never deadlock on a full pipe; past the cap the bytes are read
 * and discarded, and `truncated` records that the text is incomplete.
 */
static int msu_drain(int descriptor, struct msu_buffer *buffer) {
    char chunk[8192];
    for (;;) {
        ssize_t count = read(descriptor, chunk, sizeof(chunk));
        if (count > 0) {
            if (msu_append(buffer, chunk, (size_t)count) != 0) return -1;
            continue;
        }
        if (count == 0) return 1;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
}

static void msu_free_argv(char **argv, size_t count) {
    size_t index;
    if (argv == NULL) return;
    for (index = 0; index < count; ++index) free(argv[index]);
    free(argv);
}

static char *msu_dup_string(JNIEnv *env, jstring value) {
    const char *utf;
    char *copy;
    size_t length;
    if (value == NULL) return NULL;
    utf = (*env)->GetStringUTFChars(env, value, NULL);
    if (utf == NULL) return NULL;
    length = strlen(utf);
    copy = (char *)malloc(length + 1);
    if (copy != NULL) memcpy(copy, utf, length + 1);
    (*env)->ReleaseStringUTFChars(env, value, utf);
    return copy;
}

/* --- result marshalling --------------------------------------------------- */

static jstring msu_new_string(JNIEnv *env, const char *bytes, size_t length) {
    jclass string_class;
    jmethodID constructor;
    jbyteArray content;
    jobject charset;
    jstring result;
    if (bytes == NULL || length == 0) {
        return (*env)->NewStringUTF(env, "");
    }
    string_class = (*env)->FindClass(env, "java/lang/String");
    if (string_class == NULL) return NULL;
    constructor = (*env)->GetMethodID(env, string_class, "<init>",
                                      "([BLjava/lang/String;)V");
    if (constructor == NULL) return NULL;
    /*
     * Bytes are decoded as UTF-8 by java.lang.String, not by NewStringUTF: stdout
     * is arbitrary bytes and modified UTF-8 would either reject or mangle them.
     */
    content = (*env)->NewByteArray(env, (jsize)length);
    if (content == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, content, 0, (jsize)length, (const jbyte *)bytes);
    charset = (*env)->NewStringUTF(env, "UTF-8");
    if ((*env)->ExceptionCheck(env)) return NULL;
    if (charset == NULL) return NULL;
    result = (jstring)(*env)->NewObject(env, string_class, constructor, content, charset);
    if ((*env)->ExceptionCheck(env)) return NULL;
    return result;
}

static jobject msu_bundle(JNIEnv *env, jint code, const char *out, size_t out_length,
                          const char *err, size_t err_length) {
    jclass bundle_class;
    jmethodID constructor;
    jmethodID put_int;
    jmethodID put_string;
    jobject bundle;
    jstring out_text;
    jstring err_text;

    bundle_class = (*env)->FindClass(env, "android/os/Bundle");
    if (bundle_class == NULL) return NULL;
    constructor = (*env)->GetMethodID(env, bundle_class, "<init>", "()V");
    put_int = (*env)->GetMethodID(env, bundle_class, "putInt", "(Ljava/lang/String;I)V");
    put_string = (*env)->GetMethodID(env, bundle_class, "putString",
                                     "(Ljava/lang/String;Ljava/lang/String;)V");
    if (constructor == NULL || put_int == NULL || put_string == NULL) return NULL;
    bundle = (*env)->NewObject(env, bundle_class, constructor);
    if (bundle == NULL) return NULL;
    (*env)->CallVoidMethod(env, bundle, put_int, (*env)->NewStringUTF(env, "code"), code);
    out_text = msu_new_string(env, out, out_length);
    if (out_text != NULL) {
        (*env)->CallVoidMethod(env, bundle, put_string,
                               (*env)->NewStringUTF(env, "out"), out_text);
    }
    err_text = msu_new_string(env, err, err_length);
    if (err_text != NULL) {
        (*env)->CallVoidMethod(env, bundle, put_string,
                               (*env)->NewStringUTF(env, "err"), err_text);
    }
    /* A pending exception makes the bundle useless; let the JVM throw it. */
    if ((*env)->ExceptionCheck(env)) return NULL;
    return bundle;
}

static jobject msu_bundle_message(JNIEnv *env, jint code, const char *message) {
    return msu_bundle(env, code, "", 0, message, message != NULL ? strlen(message) : 0);
}

/* --- JNI entry ------------------------------------------------------------ */

/*
 * {code,out,err} for one command, or a bundle whose message explains why nothing
 * ran. A NULL return means the JVM could not even build the bundle; the Kotlin
 * caller maps that to SU_CLIENT_UNAVAILABLE, never to success.
 */
JNIEXPORT jobject JNICALL
Java_dev_maplesu_manager_runtime_NativeSu_run(JNIEnv *env, jobject thiz, jlong token,
                                              jobjectArray argv_array, jint timeout_ms) {
    jsize argc;
    jsize index;
    char **argv = NULL;
    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};
    pid_t child = -1;
    struct msu_buffer out;
    struct msu_buffer err;
    struct pollfd watched[2];
    int open_count = 0;
    int reaped = 0;
    int has_status = 0;
    int timed_out = 0;
    int status = 0;
    int64_t deadline;
    int code;
    jobject result;
    size_t cleanup_count;

    (void)thiz;

    memset(&out, 0, sizeof(out));
    memset(&err, 0, sizeof(err));

    if (argv_array == NULL) {
        return msu_bundle_message(env, MSU_EXIT_EXEC_FAILED, "maplesu_su: empty argv");
    }
    argc = (*env)->GetArrayLength(env, argv_array);
    if (argc <= 0) {
        return msu_bundle_message(env, MSU_EXIT_EXEC_FAILED, "maplesu_su: empty argv");
    }
    argv = (char **)calloc((size_t)argc + 1, sizeof(char *));
    if (argv == NULL) {
        return msu_bundle_message(env, MSU_EXIT_EXEC_FAILED, "maplesu_su: out of memory");
    }
    for (index = 0; index < argc; ++index) {
        jstring item = (jstring)(*env)->GetObjectArrayElement(env, argv_array, index);
        argv[index] = msu_dup_string(env, item);
        if (item != NULL) (*env)->DeleteLocalRef(env, item);
        if (argv[index] == NULL) {
            msu_free_argv(argv, (size_t)argc);
            return msu_bundle_message(env, MSU_EXIT_EXEC_FAILED,
                                      "maplesu_su: argv conversion failed");
        }
    }

    /* Concurrent children must not retain another command's output writers. */
    pthread_mutex_lock(&msu_fds_lock);
    if (pipe2(out_pipe, O_CLOEXEC) != 0) {
        pthread_mutex_unlock(&msu_fds_lock);
        msu_free_argv(argv, (size_t)argc);
        return msu_bundle_message(env, MSU_EXIT_EXEC_FAILED, "maplesu_su: pipe failed");
    }
    if (pipe2(err_pipe, O_CLOEXEC) != 0) {
        close(out_pipe[0]);
        close(out_pipe[1]);
        pthread_mutex_unlock(&msu_fds_lock);
        msu_free_argv(argv, (size_t)argc);
        return msu_bundle_message(env, MSU_EXIT_EXEC_FAILED, "maplesu_su: pipe failed");
    }

    child = fork();
    if (child < 0) {
        close(out_pipe[0]);
        close(out_pipe[1]);
        close(err_pipe[0]);
        close(err_pipe[1]);
        pthread_mutex_unlock(&msu_fds_lock);
        msu_free_argv(argv, (size_t)argc);
        return msu_bundle_message(env, MSU_EXIT_EXEC_FAILED, "maplesu_su: fork failed");
    }

    if (child == 0) {
        /*
         * Child: only async-signal-safe calls from here to execv(). The token
         * arguments are the ABI v2 SU form - (op=1, token_lo, token_hi, arg5=0) under
         * option PR_SET_DUMPABLE; the kernel checks that this task is the armed owner
         * and that the token matches before committing the pre-allocated cred.
         */
        char line[224];
        size_t at = 0;
        int prctl_result;
        int saved_errno;

        close(out_pipe[0]);
        close(err_pipe[0]);
        if (dup2(out_pipe[1], STDOUT_FILENO) < 0) _exit(MSU_EXIT_EXEC_FAILED);
        if (dup2(err_pipe[1], STDERR_FILENO) < 0) _exit(MSU_EXIT_EXEC_FAILED);
        if (out_pipe[1] != STDOUT_FILENO) close(out_pipe[1]);
        if (err_pipe[1] != STDERR_FILENO) close(err_pipe[1]);

        /*
         * ABI v2: a zero token is never magic. Issuing the call anyway would be an
         * ordinary PR_SET_DUMPABLE=1 - it returns 0 and changes the task's dumpable
         * flag - so it is refused here without touching prctl at all.
         */
        if (token == 0) {
            msu_put_text(line, &at, sizeof(line), "maplesu_su: SU denied zero token\n");
            (void)!write(STDERR_FILENO, line, at);
            _exit(MSU_EXIT_GATE_DENIED);
        }

        errno = 0;
        prctl_result = prctl(MSU_PRCTL_OPTION, (unsigned long)MSU_OP_SU,
                             (unsigned long)((uint64_t)token & 0xffffffffULL),
                             (unsigned long)((uint64_t)token >> 32), 0UL);
        saved_errno = errno;
        /*
         * ABI v2: PR_SET_DUMPABLE returns 0 for arg2 in {0,1}, so rc alone cannot
         * distinguish "the gate committed a cred" from "a plain prctl happened". Both
         * uids are proof-checked; either one not 0 is a gate denial, never success.
         */
        if (prctl_result != 0 || getuid() != 0 || geteuid() != 0) {
            msu_put_text(line, &at, sizeof(line), "maplesu_su: SU denied rc=");
            msu_put_signed(line, &at, sizeof(line), (long)prctl_result);
            msu_put_text(line, &at, sizeof(line), " errno=");
            msu_put_signed(line, &at, sizeof(line), (long)saved_errno);
            msu_put_text(line, &at, sizeof(line), " uid=");
            msu_put_unsigned(line, &at, sizeof(line), (unsigned long)getuid());
            msu_put_text(line, &at, sizeof(line), " euid=");
            msu_put_unsigned(line, &at, sizeof(line), (unsigned long)geteuid());
            line[at++] = '\n';
            (void)!write(STDERR_FILENO, line, at);
            _exit(MSU_EXIT_GATE_DENIED);
        }

        execv(argv[0], argv);

        at = 0;
        msu_put_text(line, &at, sizeof(line), "maplesu_su: exec ");
        msu_put_text(line, &at, sizeof(line), argv[0]);
        msu_put_text(line, &at, sizeof(line), " errno=");
        msu_put_signed(line, &at, sizeof(line), (long)errno);
        line[at++] = '\n';
        (void)!write(STDERR_FILENO, line, at);
        _exit(MSU_EXIT_EXEC_FAILED);
    }

    /* Parent: own both read ends, drain until EOF or the deadline. */
    close(out_pipe[1]);
    close(err_pipe[1]);
    out_pipe[1] = -1;
    err_pipe[1] = -1;
    pthread_mutex_unlock(&msu_fds_lock);
    {
        int flags = fcntl(out_pipe[0], F_GETFL, 0);
        if (flags >= 0) (void)fcntl(out_pipe[0], F_SETFL, flags | O_NONBLOCK);
        flags = fcntl(err_pipe[0], F_GETFL, 0);
        if (flags >= 0) (void)fcntl(err_pipe[0], F_SETFL, flags | O_NONBLOCK);
    }
    deadline = msu_now_ms() + (timeout_ms > 0 ? (int64_t)timeout_ms
                                              : (int64_t)MSU_DEFAULT_TIMEOUT_MS);
    watched[0].fd = out_pipe[0];
    watched[0].events = POLLIN;
    watched[0].revents = 0;
    watched[1].fd = err_pipe[0];
    watched[1].events = POLLIN;
    watched[1].revents = 0;
    open_count = 2;
    while (open_count > 0) {
        int64_t remaining = deadline - msu_now_ms();
        int ready;
        int slot;
        if (remaining <= 0) {
            timed_out = 1;
            break;
        }
        ready = poll(watched, 2, (int)(remaining > 60000 ? 60000 : remaining));
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ready == 0) continue;
        for (slot = 0; slot < 2; ++slot) {
            int drained;
            if (watched[slot].fd < 0) continue;
            if ((watched[slot].revents & (POLLIN | POLLHUP | POLLERR)) == 0) continue;
            drained = msu_drain(watched[slot].fd, slot == 0 ? &out : &err);
            if (drained != 0) {
                close(watched[slot].fd);
                watched[slot].fd = -1;
                --open_count;
            }
        }
    }
    if (watched[0].fd >= 0) close(watched[0].fd);
    if (watched[1].fd >= 0) close(watched[1].fd);

    /* Reap, with whatever time is left. A child that outlives it is killed. */
    while (!reaped) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        int64_t remaining;
        if (waited == child) {
            reaped = 1;
            has_status = 1;
            break;
        }
        if (waited < 0 && errno != EINTR) break;
        remaining = deadline - msu_now_ms();
        if (remaining <= 0) break;
        {
            struct timespec pause;
            pause.tv_sec = 0;
            pause.tv_nsec = 10 * 1000 * 1000;
            (void)nanosleep(&pause, NULL);
        }
    }
    if (!reaped) {
        timed_out = 1;
        (void)kill(child, SIGKILL);
        for (;;) {
            pid_t waited = waitpid(child, &status, 0);
            if (waited == child) {
                has_status = 1;
                break;
            }
            if (waited < 0 && errno == EINTR) continue;
            break;
        }
        reaped = 1;
    }

    if (timed_out) {
        static const char timeout_note[] = "\nmaplesu_su: timeout\n";
        code = MSU_EXIT_TIMEOUT;
        (void)msu_append(&err, timeout_note, sizeof(timeout_note) - 1);
    } else if (!has_status) {
        /* The child could not be reaped at all: never report that as success. */
        code = -1;
    } else if (WIFEXITED(status)) {
        code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        code = 128 + WTERMSIG(status);
    } else {
        code = -1;
    }

    if (out.truncated) {
        static const char note[] = "\nmaplesu_su: stdout truncated\n";
        (void)msu_append(&out, note, sizeof(note) - 1);
    }
    if (err.truncated) {
        static const char note[] = "\nmaplesu_su: stderr truncated\n";
        (void)msu_append(&err, note, sizeof(note) - 1);
    }

    result = msu_bundle(env, (jint)code, out.data, out.length, err.data, err.length);

    cleanup_count = (size_t)argc;
    msu_free_argv(argv, cleanup_count);
    free(out.data);
    free(err.data);
    return result;
}

/* ===========================================================================
 * Streaming form (third-party `su` proxy, design §4.2).
 *
 * The one-shot entry above captures output into two parent-owned pipes and never
 * forwards the caller's stdin, so proxying an interactive `su` with it would silently
 * drop input. The third-party ABI (INativeSuService) hands the endpoint three descriptors
 * that belong to *its* caller, so the child must inherit exactly those.
 *
 * Shape: startStreaming() forks a child that is blocked on a control pipe before it has
 * armed anything; the parent decides (re-reads the Manager's list), then commit() writes
 * one byte to let the child arm the gate and exec, or abort() closes the pipe so the
 * child exits 126 without ever calling prctl. That is the proxy's TOCTOU window: the
 * decision is re-read while the child exists but before the child can become root.
 *
 * The control descriptor never reaches the child's exec (O_CLOEXEC) and the token is
 * only ever a jlong argument of the child's prctl - it is not put in argv, the
 * environment, a log line or the descriptor table.
 * ======================================================================== */

#define MSU_MAX_STREAM 16

struct msu_stream_slot {
    pid_t pid;   /* 0 = free */
    int control; /* parent's write end; -1 = free */
};

static struct msu_stream_slot msu_streams[MSU_MAX_STREAM];
static pthread_mutex_t msu_streams_lock = PTHREAD_MUTEX_INITIALIZER;

/* Returns 0 on success, -1 when the table is full (8 live children per ART process). */
static int msu_stream_store(pid_t pid, int control) {
    int index;
    int stored = -1;
    pthread_mutex_lock(&msu_streams_lock);
    for (index = 0; index < MSU_MAX_STREAM; ++index) {
        if (msu_streams[index].pid == 0) {
            msu_streams[index].pid = pid;
            msu_streams[index].control = control;
            stored = 0;
            break;
        }
    }
    pthread_mutex_unlock(&msu_streams_lock);
    return stored;
}

/* Removes the slot and returns the parent's write end, or -1 when the pid is unknown. */
static int msu_stream_take(pid_t pid) {
    int index;
    int control = -1;
    pthread_mutex_lock(&msu_streams_lock);
    for (index = 0; index < MSU_MAX_STREAM; ++index) {
        if (msu_streams[index].pid == pid) {
            control = msu_streams[index].control;
            msu_streams[index].pid = 0;
            msu_streams[index].control = -1;
            break;
        }
    }
    pthread_mutex_unlock(&msu_streams_lock);
    return control;
}

/* Child side: every inherited control write end must be closed before exec. */
static void msu_stream_close_inherited(void) {
    int index;
    for (index = 0; index < MSU_MAX_STREAM; ++index) {
        if (msu_streams[index].pid != 0 && msu_streams[index].control >= 0) {
            close(msu_streams[index].control);
            msu_streams[index].control = -1;
        }
    }
}

static int msu_write_all(int descriptor, const char *bytes, size_t length) {
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(descriptor, bytes + written, length - written);
        if (count <= 0) {
            if (count < 0 && errno == EINTR) continue;
            return -1;
        }
        written += (size_t)count;
    }
    return 0;
}

/*
 * Blocks until one byte arrives or the pipe is closed. Returns the byte, or -1 when the
 * parent aborted (EOF). Only async-signal-safe calls happen here: this runs between
 * fork() and execv() in a multi-threaded ART process.
 */
static int msu_wait_control(int descriptor) {
    unsigned char value = 0;
    for (;;) {
        ssize_t count = read(descriptor, &value, 1);
        if (count == 1) return (int)value;
        if (count == 0) return -1;
        if (errno == EINTR) continue;
        return -1;
    }
}

static int msu_redirect(int source, int target) {
    int descriptor = source;
    if (descriptor < 0) {
        descriptor = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (descriptor < 0) return -1;
    }
    if (descriptor != target) {
        if (dup2(descriptor, target) < 0) {
            close(descriptor);
            return -1;
        }
        close(descriptor);
    }
    return 0;
}

/* The child's whole life before exec: redirect, wait, arm, prove, exec. */
static void msu_stream_child(jlong token, char **argv, int in_fd, int out_fd, int err_fd,
                             int control_read, int global_mnt) {
    char line[224];
    size_t at = 0;
    int prctl_result;
    int saved_errno;

    msu_stream_close_inherited();
    /*
     * Manager death must not leave a root child behind. PR_SET_PDEATHSIG is inherited
     * across exec for this child (Linux semantics), so the exec'd program carries it too.
     */
    (void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0UL, 0UL, 0UL);
    if (msu_redirect(in_fd, STDIN_FILENO) != 0) _exit(MSU_EXIT_EXEC_FAILED);
    if (msu_redirect(out_fd, STDOUT_FILENO) != 0) _exit(MSU_EXIT_EXEC_FAILED);
    if (msu_redirect(err_fd, STDERR_FILENO) != 0) _exit(MSU_EXIT_EXEC_FAILED);

    /* The decision is taken by the parent while this blocks. EOF or 0 = refused. */
    if (msu_wait_control(control_read) != 1) {
        close(control_read);
        _exit(MSU_EXIT_GATE_DENIED);
    }
    close(control_read);

    if (token == 0) {
        msu_put_text(line, &at, sizeof(line), "maplesu_su: SU denied zero token\n");
        (void)!write(STDERR_FILENO, line, at);
        _exit(MSU_EXIT_GATE_DENIED);
    }
    errno = 0;
    prctl_result = prctl(MSU_PRCTL_OPTION, (unsigned long)MSU_OP_SU,
                         (unsigned long)((uint64_t)token & 0xffffffffULL),
                         (unsigned long)((uint64_t)token >> 32), 0UL);
    saved_errno = errno;
    if (prctl_result != 0 || getuid() != 0 || geteuid() != 0) {
        at = 0;
        msu_put_text(line, &at, sizeof(line), "maplesu_su: SU denied rc=");
        msu_put_signed(line, &at, sizeof(line), (long)prctl_result);
        msu_put_text(line, &at, sizeof(line), " errno=");
        msu_put_signed(line, &at, sizeof(line), (long)saved_errno);
        msu_put_text(line, &at, sizeof(line), " uid=");
        msu_put_unsigned(line, &at, sizeof(line), (unsigned long)getuid());
        msu_put_text(line, &at, sizeof(line), " euid=");
        msu_put_unsigned(line, &at, sizeof(line), (unsigned long)geteuid());
        line[at++] = '\n';
        (void)!write(STDERR_FILENO, line, at);
        _exit(MSU_EXIT_GATE_DENIED);
    }
    /*
     * Only root may enter init's mount namespace, so this has to happen after the prctl.
     * A failure is reported, never ignored: mounting globally is part of what the caller
     * asked for, and a child in the wrong namespace would run the command in the wrong
     * view of the file system.
     */
    if (global_mnt) {
        int namespace_fd = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
        int entered = -1;
        errno = 0;
        if (namespace_fd >= 0) {
            entered = setns(namespace_fd, 0);
            close(namespace_fd);
        }
        if (entered != 0) {
            at = 0;
            msu_put_text(line, &at, sizeof(line), "maplesu_su: global mount namespace denied errno=");
            msu_put_signed(line, &at, sizeof(line), (long)errno);
            line[at++] = '\n';
            (void)!write(STDERR_FILENO, line, at);
            _exit(MSU_EXIT_EXEC_FAILED);
        }
    }
    execv(argv[0], argv);
    at = 0;
    msu_put_text(line, &at, sizeof(line), "maplesu_su: exec ");
    msu_put_text(line, &at, sizeof(line), argv[0]);
    msu_put_text(line, &at, sizeof(line), " errno=");
    msu_put_signed(line, &at, sizeof(line), (long)errno);
    line[at++] = '\n';
    (void)!write(STDERR_FILENO, line, at);
    _exit(MSU_EXIT_EXEC_FAILED);
}

/*
 * startStreaming: fork a child that is blocked on the control pipe and return its pid.
 *
 * Returns the pid (>0) or a negative transport error: -1 argv/JVM, -2 zero token,
 * -3 fork/pipe, -4 too many live children. Nothing is executed on any error path.
 */
JNIEXPORT jlong JNICALL
Java_dev_maplesu_manager_runtime_NativeSu_startStreaming(JNIEnv *env, jobject thiz, jlong token,
                                                         jobjectArray argv_array, jint in_fd,
                                                         jint out_fd, jint err_fd,
                                                         jboolean global_mnt) {
    jsize argc;
    jsize index;
    char **argv = NULL;
    int control[2] = {-1, -1};
    pid_t child = -1;

    (void)thiz;
    (void)in_fd;
    (void)out_fd;
    (void)err_fd;
    (void)global_mnt;

    if (token == 0) return -2;
    if (argv_array == NULL) return -1;
    argc = (*env)->GetArrayLength(env, argv_array);
    if (argc <= 0) return -1;
    argv = (char **)calloc((size_t)argc + 1, sizeof(char *));
    if (argv == NULL) return -1;
    for (index = 0; index < argc; ++index) {
        jstring item = (jstring)(*env)->GetObjectArrayElement(env, argv_array, index);
        argv[index] = msu_dup_string(env, item);
        if (item != NULL) (*env)->DeleteLocalRef(env, item);
        if (argv[index] == NULL) {
            msu_free_argv(argv, (size_t)argc);
            return -1;
        }
    }
    pthread_mutex_lock(&msu_fds_lock);
    if (pipe2(control, O_CLOEXEC) != 0) {
        pthread_mutex_unlock(&msu_fds_lock);
        msu_free_argv(argv, (size_t)argc);
        return -3;
    }
    child = fork();
    if (child < 0) {
        close(control[0]);
        close(control[1]);
        pthread_mutex_unlock(&msu_fds_lock);
        msu_free_argv(argv, (size_t)argc);
        return -3;
    }
    if (child == 0) {
        /* control[0] stays open for the wait; control[1] is the parent's. */
        close(control[1]);
        msu_stream_child(token, argv, in_fd, out_fd, err_fd, control[0],
                         global_mnt ? 1 : 0);
        _exit(MSU_EXIT_EXEC_FAILED);
    }
    close(control[0]);
    if (msu_stream_store(child, control[1]) != 0) {
        /* Refuse before anything can be armed: closing the pipe makes the child exit 126. */
        close(control[1]);
        pthread_mutex_unlock(&msu_fds_lock);
        (void)waitpid(child, NULL, 0);
        msu_free_argv(argv, (size_t)argc);
        return -4;
    }
    pthread_mutex_unlock(&msu_fds_lock);
    /*
     * The parent no longer needs the argv or the caller's descriptors: the child has its
     * own copy of the address space, and its descriptors were inherited at fork. The
     * caller closes what it passed in.
     */
    msu_free_argv(argv, (size_t)argc);
    return (jlong)child;
}

/* commitStreaming: one byte admits the prepared child. 1 = released, 0 = unknown pid. */
JNIEXPORT jboolean JNICALL
Java_dev_maplesu_manager_runtime_NativeSu_commitStreaming(JNIEnv *env, jobject thiz, jlong pid) {
    static const char admitted = 1;
    int control;
    int written;
    int saved_errno;
    (void)thiz;
    (void)env;
    pthread_mutex_lock(&msu_fds_lock);
    control = msu_stream_take((pid_t)pid);
    if (control < 0) {
        pthread_mutex_unlock(&msu_fds_lock);
        return JNI_FALSE;
    }
    errno = 0;
    written = msu_write_all(control, &admitted, 1);
    saved_errno = errno;
    close(control);
    pthread_mutex_unlock(&msu_fds_lock);
    if (written != 0) {
        (void)saved_errno;
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

/* abortStreaming: refuses a prepared child (it exits 126 without ever calling prctl). */
JNIEXPORT void JNICALL
Java_dev_maplesu_manager_runtime_NativeSu_abortStreaming(JNIEnv *env, jobject thiz, jlong pid) {
    static const char refused = 0;
    int control;
    (void)thiz;
    (void)env;
    pthread_mutex_lock(&msu_fds_lock);
    control = msu_stream_take((pid_t)pid);
    if (control < 0) {
        pthread_mutex_unlock(&msu_fds_lock);
        return;
    }
    (void)msu_write_all(control, &refused, 1);
    close(control);
    pthread_mutex_unlock(&msu_fds_lock);
}

/*
 * reaping: waits up to timeout_ms. Returns the exit code (0..255, 128+signal when killed),
 * -2 when the child is still running at the deadline, -1 on a wait error.
 */
JNIEXPORT jint JNICALL
Java_dev_maplesu_manager_runtime_NativeSu_reapStreaming(JNIEnv *env, jobject thiz, jlong pid,
                                                        jint timeout_ms) {
    int status = 0;
    int64_t deadline;
    (void)thiz;
    (void)env;
    deadline = msu_now_ms() + (timeout_ms > 0 ? (int64_t)timeout_ms : 0);
    for (;;) {
        pid_t waited = waitpid((pid_t)pid, &status, WNOHANG);
        if (waited == (pid_t)pid) break;
        if (waited < 0 && errno != EINTR) return -1;
        if (timeout_ms <= 0) return -2;
        if (msu_now_ms() >= deadline) return -2;
        {
            struct timespec pause;
            pause.tv_sec = 0;
            pause.tv_nsec = 10 * 1000 * 1000;
            (void)nanosleep(&pause, NULL);
        }
    }
    if (WIFEXITED(status)) return (jint)WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return (jint)(128 + WTERMSIG(status));
    return -1;
}

/* killStreaming: sends one signal; SIGKILL also reaps so no zombie survives the session. */
JNIEXPORT jint JNICALL
Java_dev_maplesu_manager_runtime_NativeSu_killStreaming(JNIEnv *env, jobject thiz, jlong pid,
                                                        jint signal_number) {
    int result;
    int control;
    (void)thiz;
    (void)env;
    /* A still-prepared child is stopped through its control pipe, not by a signal race. */
    pthread_mutex_lock(&msu_fds_lock);
    control = msu_stream_take((pid_t)pid);
    if (control >= 0) {
        static const char refused = 0;
        (void)msu_write_all(control, &refused, 1);
        close(control);
    }
    pthread_mutex_unlock(&msu_fds_lock);
    result = kill((pid_t)pid, signal_number);
    if (signal_number == SIGKILL) {
        for (;;) {
            pid_t waited = waitpid((pid_t)pid, NULL, 0);
            if (waited == (pid_t)pid) break;
            if (waited < 0 && errno == EINTR) continue;
            break;
        }
    }
    return result == 0 ? 0 : -1;
}
