/*
 * maplesu-umh-canary -- the step-2 canary helper.
 *
 * The kernel module (maplesu_root.ko) execs this file as kernel-domain root
 * (init_cred, u:r:kernel:s0) during the SELinux-permissive handover window.
 * Everything it does is:
 *
 *   (a) poll briefly for the module's post-exec printks and copy every tagged
 *       kernel line to the App-owned provider log (DEV-164, see below)
 *   (b) write "1" to /sys/fs/selinux/enforce      -- close the window
 *   (c) read /sys/fs/selinux/enforce back and verify "1"
 *   (d) write one ASCII marker line to /dev/kmsg (best effort)
 *   (e) exit 0
 *
 * It never starts ART or app_process, never mounts, never writes a boot image or
 * a block device, never forks, never execs and never unlinks anything. The only
 * paths it can name are the four compiled into it (see the whitelist gate in
 * build_canary_helper.py).
 *
 * Ordering matters, and it is deliberate
 * --------------------------------------
 * Restoring enforcement makes SELinux enforce again for everything this process
 * does afterwards. Its domain is u:r:kernel:s0, which is not granted write access
 * to app data, so a log file opened *after* the restore could be denied. Every
 * descriptor is therefore opened while the window is still open, and the restore
 * happens in the middle: "open all sinks -> write the enforcement byte -> read it
 * back through an already-open descriptor -> write the markers through the
 * already-open descriptors". No filesystem lookup happens after enforcement is
 * back on. (This is also why the bootstrap's own post-restore log lines land: an
 * already-open file descriptor is not re-validated when the policy has not
 * changed.)
 *
 * Why a second marker sink exists
 * -------------------------------
 * The plan's acceptance evidence is read from the App-owned provider log
 * (/data/user_de/0/dev.maplesu.manager/maplesu-provider.log): this build denies
 * `dmesg` to every unprivileged reader, so the kernel ring buffer is not a
 * collectable channel on this device, and `ir_probe_file()` only dumps the ring
 * buffer when a probe *fails*. The helper therefore appends one marker line, with
 * the observed values, to that log file as well (best effort; a missing or
 * unwritable file changes nothing). Build with -DMAPLESU_CANARY_KMSG_ONLY for the
 * strict kmsg-only variant.
 *
 * Why the helper also copies kernel lines (DEV-164)
 * ------------------------------------------------
 * The bootstrap's success-path ring-buffer dump runs *after* this helper has
 * restored enforce=1, and it runs as u:r:kernel:s0, a domain that is denied
 * app-data lookups once the policy is back - on attempt #1 that denial hit the
 * dump's own `access()` precondition, so the `maplesu_root:` lines of the one
 * successful run never reached the log. This helper is inside the window and
 * already holds the log descriptor, so it copies the module's tagged lines before
 * restoring. It polls at most 150 ms because `maplesu_root: umh setup=...
 * ret=0` / `maplesu_root: handover started; resident` are printed after exec()
 * returns, i.e. while this process is already running; the wait ends as soon as
 * the success line is visible, so the window normally stays in the low
 * milliseconds. The dump is bounded (line count and bytes) and best effort: a
 * failed read or a missing log file never delays the restore, which is still the
 * first thing that must happen once the capture is done.
 *
 * Freestanding: no libc, no crt, no dynamic linker, raw syscalls only. The host
 * build script asserts the result has no undefined symbols, no DT_NEEDED and no
 * PT_INTERP, so a libc dependency cannot creep in unnoticed.
 */

typedef unsigned long u64;
typedef long i64;

/* aarch64 generic syscall numbers (include/uapi/asm-generic/unistd.h). */
#define SYS_openat 56
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_nanosleep 101
#define SYS_getuid 174
/* The same number/action pair the bootstrap uses (MAPLESU_NR_SYSLOG /
 * MAPLESU_SYSLOG_READ_ALL): copied as a value on purpose, no kernel header. */
#define SYS_syslog 116
#define SYSLOG_READ_ALL 3

#define AT_FDCWD (-100L)
#define O_RDONLY 0L
#define O_WRONLY 1L
#define O_CREAT 0100L
#define O_APPEND 02000L
#define O_CLOEXEC 02000000L

#define ENFORCE_PATH "/sys/fs/selinux/enforce"
#define KMSG_PATH "/dev/kmsg"
#define DOMAIN_PATH "/proc/self/attr/current"

#ifndef MAPLESU_CANARY_KMSG_ONLY
/* The bootstrap's MAPLESU_LOG_PRIMARY (jailbreak-providers/dirtyfrag/adapter/
 * bootstrap.c:22). An evidence channel, not a privileged action. */
#define PROVIDER_LOG_PATH "/data/user_de/0/dev.maplesu.manager/maplesu-provider.log"
#endif

#define LINE_MAX 512
#define SMALL_MAX 128

#ifndef MAPLESU_CANARY_KMSG_ONLY
/*
 * Kernel-line capture (DEV-164). The ring buffer is read with the same
 * syslog(READ_ALL) raw syscall the bootstrap uses, and only the module's own tag
 * lines are kept, so the provider log stays bounded however noisy the kernel is.
 * The poll is a bounded wait for the module's post-exec printks: `umh setup=...
 * ret=0` and `handover started; resident` are printed after exec() returns, i.e.
 * while this process already runs, and the wait ends the moment the success line
 * is visible.
 */
#define KLOG_CAPACITY (64 * 1024)
#define KLOG_POLL_STEPS 15
#define KLOG_POLL_STEP_NS 10000000L /* 10 ms per step -> at most 150 ms */
#define KLOG_MAX_LINES 64
#define KLOG_MAX_BYTES 8192
#define KLOG_LINE_MAX 400
#define KLOG_PREFIX "maplesu-umh-canary: kernel | "
#define KLOG_TAG_MODULE "maplesu_root:"
#define KLOG_TAG_HELPER "maplesu-umh-canary:"
#define KLOG_SUCCESS_LINE "maplesu_root: handover started"

static char klog_buffer[KLOG_CAPACITY];
#endif

static inline i64 sys4(i64 nr, i64 a, i64 b, i64 c, i64 d)
{
	register i64 x8 __asm__("x8") = nr;
	register i64 x0 __asm__("x0") = a;
	register i64 x1 __asm__("x1") = b;
	register i64 x2 __asm__("x2") = c;
	register i64 x3 __asm__("x3") = d;

	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
			 : "memory");
	return x0;
}

static i64 sys_open(const char *path, i64 flags, i64 mode)
{
	return sys4(SYS_openat, AT_FDCWD, (i64)path, flags, mode);
}

static i64 sys_read(i64 fd, void *buffer, u64 length)
{
	return sys4(SYS_read, fd, (i64)buffer, (i64)length, 0);
}

static i64 sys_write(i64 fd, const void *buffer, u64 length)
{
	return sys4(SYS_write, fd, (i64)buffer, (i64)length, 0);
}

static void sys_close(i64 fd)
{
	if (fd >= 0)
		(void)sys4(SYS_close, fd, 0, 0, 0);
}

/* Bounded append-only builder; every put_* stops at the buffer end. */
struct line {
	char text[LINE_MAX];
	u64 used;
};

static void line_reset(struct line *line)
{
	line->used = 0;
	line->text[0] = '\0';
}

static void put_text(struct line *line, const char *text)
{
	for (u64 i = 0; text[i] != '\0' && line->used + 1 < LINE_MAX; ++i)
		line->text[line->used++] = text[i];
	line->text[line->used] = '\0';
}

static void put_unsigned(struct line *line, u64 value)
{
	char digits[24];
	u64 count = 0;

	do {
		digits[count++] = (char)('0' + (value % 10));
		value /= 10;
	} while (value != 0 && count < sizeof(digits));
	while (count > 0 && line->used + 1 < LINE_MAX)
		line->text[line->used++] = digits[--count];
	line->text[line->used] = '\0';
}

static void put_signed(struct line *line, i64 value)
{
	if (value < 0) {
		put_text(line, "-");
		put_unsigned(line, (u64)(-value));
		return;
	}
	put_unsigned(line, (u64)value);
}

static void put_newline(struct line *line)
{
	if (line->used + 1 < LINE_MAX) {
		line->text[line->used++] = '\n';
		line->text[line->used] = '\0';
	}
}

#ifndef MAPLESU_CANARY_KMSG_ONLY
struct interval {
	i64 seconds;
	i64 nanoseconds;
};

static void sleep_step(void)
{
	struct interval wait = {0, KLOG_POLL_STEP_NS};

	(void)sys4(SYS_nanosleep, (i64)&wait, 0, 0, 0);
}

/* Literal substring search bounded by length; 1 on a match. */
static int contains_text(const char *haystack, i64 length, const char *needle)
{
	i64 needle_length = 0;

	while (needle[needle_length] != '\0')
		++needle_length;
	if (needle_length == 0 || length < needle_length)
		return 0;
	for (i64 start = 0; start + needle_length <= length; ++start) {
		i64 offset = 0;

		while (offset < needle_length &&
		       haystack[start + offset] == needle[offset])
			++offset;
		if (offset == needle_length)
			return 1;
	}
	return 0;
}

/*
 * Copy every tagged line to the provider log as `<prefix><line>\n`. Bounded by
 * line count and total bytes, so a flood of module lines can never delay the
 * restore for long. Returns the number of lines copied; *bytes_out is what was
 * appended.
 */
static i64 capture_kernel_lines(i64 fd, i64 count, i64 *bytes_out)
{
	i64 lines = 0;
	i64 bytes = 0;
	i64 cursor = 0;

	*bytes_out = 0;
	if (fd < 0 || count <= 0)
		return 0;
	while (cursor < count && lines < KLOG_MAX_LINES && bytes < KLOG_MAX_BYTES) {
		i64 end = cursor;
		i64 length;

		while (end < count && klog_buffer[end] != '\n')
			++end;
		length = end - cursor;
		if (length > 0 &&
		    (contains_text(klog_buffer + cursor, length, KLOG_TAG_MODULE) ||
		     contains_text(klog_buffer + cursor, length, KLOG_TAG_HELPER))) {
			const i64 kept = length > KLOG_LINE_MAX ? KLOG_LINE_MAX : length;

			(void)sys_write(fd, KLOG_PREFIX, sizeof(KLOG_PREFIX) - 1);
			(void)sys_write(fd, klog_buffer + cursor, (u64)kept);
			(void)sys_write(fd, "\n", 1);
			bytes += (i64)(sizeof(KLOG_PREFIX) - 1) + kept + 1;
			++lines;
		}
		cursor = end + 1;
	}
	*bytes_out = bytes;
	return lines;
}

/* One stable summary line, so a run can be judged from the log alone. */
static void emit_kernel_summary(i64 fd, i64 lines, i64 bytes, i64 polls, i64 read)
{
	struct line summary;

	if (fd < 0)
		return;
	line_reset(&summary);
	put_text(&summary, "maplesu-umh-canary: kernel summary lines=");
	put_signed(&summary, lines);
	put_text(&summary, " bytes=");
	put_signed(&summary, bytes);
	put_text(&summary, " polls=");
	put_signed(&summary, polls);
	put_text(&summary, " read=");
	put_signed(&summary, read);
	put_newline(&summary);
	(void)sys_write(fd, summary.text, summary.used);
}

/*
 * Bounded wait, then one copy of the tagged lines. Returns the byte count of the
 * last READ_ALL (negative on failure); *polls_out is the number of syslog calls,
 * *lines_out / *bytes_out describe what reached the provider log.
 */
static i64 capture_kernel_window(i64 log_fd, i64 *polls_out, i64 *lines_out,
				 i64 *bytes_out)
{
	i64 read_bytes = -1;
	i64 polls = 0;

	while (polls < KLOG_POLL_STEPS) {
		read_bytes = sys4(SYS_syslog, SYSLOG_READ_ALL, (i64)klog_buffer,
				  (i64)KLOG_CAPACITY, 0);
		++polls;
		if (read_bytes > 0 &&
		    contains_text(klog_buffer, read_bytes, KLOG_SUCCESS_LINE))
			break;
		if (polls < KLOG_POLL_STEPS)
			sleep_step();
	}
	*polls_out = polls;
	*lines_out = read_bytes > 0 ? capture_kernel_lines(log_fd, read_bytes, bytes_out) : 0;
	if (read_bytes <= 0)
		*bytes_out = 0;
	return read_bytes;
}
#endif /* MAPLESU_CANARY_KMSG_ONLY */

/* Read one small text attribute to a NUL-terminated string; -1 on failure. */
static i64 read_small_path(const char *path, char *buffer, u64 capacity)
{
	const i64 fd = sys_open(path, O_RDONLY | O_CLOEXEC, 0);
	i64 total = 0;

	if (fd < 0)
		return -1;
	while ((u64)total + 1 < capacity) {
		const i64 got = sys_read(fd, buffer + total, capacity - 1 - (u64)total);
		if (got <= 0)
			break;
		total += got;
	}
	sys_close(fd);
	buffer[total] = '\0';
	while (total > 0 && (buffer[total - 1] == '\n' || buffer[total - 1] == '\r'))
		buffer[--total] = '\0';
	return total;
}

/* The same read through a descriptor opened earlier, so no lookup happens after
 * the enforcement restore. */
static int read_byte_fd(i64 fd)
{
	char value = -1;

	if (fd < 0 || sys_read(fd, &value, 1) != 1)
		return -1;
	if (value != '0' && value != '1')
		return -1;
	return value == '1' ? 1 : 0;
}

static int read_enforce_now(void)
{
	char value[8];

	if (read_small_path(ENFORCE_PATH, value, sizeof(value)) != 1)
		return -1;
	if (value[0] != '0' && value[0] != '1')
		return -1;
	return value[0] == '1' ? 1 : 0;
}

/*
 * One marker line per sink. `ok` is 1 only when the write reported one byte AND
 * the readback is Enforcing; anything else is reported as FAILED with the
 * observed values, so the log alone distinguishes "helper never ran" from
 * "helper ran but the restore failed".
 */
static void build_marker(struct line *line, int ok, u64 uid, const char *domain,
			 int before, int readback, int wrote)
{
	line_reset(line);
	if (ok) {
		put_text(line, "maplesu-umh-canary: handover ok uid=");
		put_unsigned(line, uid);
		put_text(line, " domain=");
		put_text(line, domain);
		put_text(line, " enforce_before=");
		put_signed(line, before);
		put_text(line, " readback=");
		put_signed(line, readback);
	} else {
		put_text(line, "maplesu-umh-canary: FAILED uid=");
		put_unsigned(line, uid);
		put_text(line, " domain=");
		put_text(line, domain);
		put_text(line, " enforce_before=");
		put_signed(line, before);
		put_text(line, " wrote=");
		put_signed(line, wrote);
		put_text(line, " readback=");
		put_signed(line, readback);
	}
	put_newline(line);
}

/* The mandated marker sink: the kernel ring buffer. */
static void emit_kmsg(i64 fd, int readback)
{
	struct line line;

	if (fd < 0)
		return;
	line_reset(&line);
	put_text(&line, "<6>maplesu_root: canary helper restored enforce=");
	put_signed(&line, readback);
	put_newline(&line);
	(void)sys_write(fd, line.text, line.used);
}

void _start(void)
{
	char domain[SMALL_MAX];
	struct line marker;
	const u64 uid = (u64)sys4(SYS_getuid, 0, 0, 0, 0);
	i64 kmsg_fd = -1;
#ifndef MAPLESU_CANARY_KMSG_ONLY
	i64 log_fd = -1;
	i64 klog_polls = 0, klog_lines = 0, klog_bytes = 0;
#endif
	i64 write_fd = -1, read_fd = -1;
	int before, readback, wrote, ok;

	/* Prove the permissive window was open when this process started. */
	before = read_enforce_now();

	/* Every descriptor this helper will ever use is opened *now*, while the
	 * window is open; nothing is looked up after the capture and before the
	 * restore. */
	kmsg_fd = sys_open(KMSG_PATH, O_WRONLY | O_CLOEXEC, 0);
#ifndef MAPLESU_CANARY_KMSG_ONLY
	log_fd = sys_open(PROVIDER_LOG_PATH,
			  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
#endif
	write_fd = sys_open(ENFORCE_PATH, O_WRONLY | O_CLOEXEC, 0);
	read_fd = sys_open(ENFORCE_PATH, O_RDONLY | O_CLOEXEC, 0);

	if (read_small_path(DOMAIN_PATH, domain, sizeof(domain)) <= 0)
		domain[0] = '\0';
	if (domain[0] == '\0') {
		domain[0] = '?';
		domain[1] = '\0';
	}

#ifndef MAPLESU_CANARY_KMSG_ONLY
	/*
	 * (a) kernel-side capture, still inside the window and through the log
	 * descriptor opened above. This is the belt-and-braces half of DEV-164: the
	 * bootstrap's own dump runs after this process restored enforce=1, from a
	 * kernel-domain process that is then denied app-data lookups. Reading here
	 * cannot be denied, and it costs at most 150 ms (normally the first poll
	 * already sees `maplesu_root: handover started`). The restore below is still
	 * unconditional and immediate once the capture returns.
	 */
	{
		const i64 klog_read = capture_kernel_window(log_fd, &klog_polls,
							    &klog_lines, &klog_bytes);

		emit_kernel_summary(log_fd, klog_lines, klog_bytes, klog_polls, klog_read);
	}
#endif

	/* (b) close the window. */
	wrote = (write_fd >= 0 && sys_write(write_fd, "1", 1) == 1) ? 1 : 0;

	/* (c) the readback is the evidence, not the write. */
	readback = read_byte_fd(read_fd);
	ok = (wrote == 1 && readback == 1) ? 1 : 0;

	build_marker(&marker, ok, uid, domain, before, readback, wrote);

	/* (d) markers, both through descriptors opened during the window. */
	emit_kmsg(kmsg_fd, readback);
#ifndef MAPLESU_CANARY_KMSG_ONLY
	if (log_fd >= 0)
		(void)sys_write(log_fd, marker.text, marker.used);
#endif

	sys_close(read_fd);
	sys_close(write_fd);
#ifndef MAPLESU_CANARY_KMSG_ONLY
	sys_close(log_fd);
#endif
	sys_close(kmsg_fd);

	/* (e) exit. 0 is the success chain; a failed restore exits 1 so an in-band
	 * observer (if one ever exists) sees it. UMH_WAIT_EXEC never reads this. */
	sys4(SYS_exit, ok ? 0 : 1, 0, 0, 0);
	for (;;)
		; /* unreachable */
}
