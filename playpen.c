#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <linux/limits.h>
#include <pwd.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/timerfd.h>
#include <sys/reg.h>
#include <sys/wait.h>

#include <seccomp.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>

enum learn {
    LEARN_NONE,
    LEARN_FINE,
    LEARN_COARSE
};

static void check(int rc) {
    if (rc < 0) errx(EXIT_FAILURE, "%s", strerror(-rc));
}

__attribute__((format(printf, 2, 3))) static void check_posix(intmax_t rc, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (rc == -1) verr(EXIT_FAILURE, fmt, args);
    va_end(args);
}

__attribute__((format(printf, 2, 3))) static bool check_eagain(intmax_t rc, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (rc == -1 && errno != EAGAIN) verr(EXIT_FAILURE, fmt, args);
    va_end(args);
    return rc == -1 && errno == EAGAIN;
}

__attribute__((format(printf, 2, 3))) static void asprintfx(char **strp, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (vasprintf(strp, fmt, args) == -1) {
        errx(EXIT_FAILURE, "asprintf: %s", strerror(ENOMEM));
    }
    va_end(args);
}

static char *join_path(const char *left, const char *right) {
    char *dst;
    asprintfx(&dst, "%s/%s", left, right);
    return dst;
}

static void mountx(const char *source, const char *target, const char *filesystemtype,
                   unsigned long mountflags, const void *data) {
    check_posix(mount(source, target, filesystemtype, mountflags, data),
                "mounting %s as %s (%s) failed", source, target, filesystemtype);
}

struct bind_list {
    struct bind_list *next;
    bool read_only;
    char arg[];
};

static struct bind_list *bind_list_alloc(const char *arg, bool read_only) {
    size_t len = strlen(arg);
    struct bind_list *next = malloc(sizeof(struct bind_list) + len + 1);
    if (!next) err(EXIT_FAILURE, "malloc");

    next->next = NULL;
    next->read_only = read_only;
    strcpy(next->arg, arg);
    return next;
}

static void bind_list_apply(const char *root, struct bind_list *list) {
    for (; list; list = list->next) {
        char *dst = join_path(root, list->arg);
        // Only use MS_REC with writable mounts to work around a kernel bug:
        // https://bugzilla.kernel.org/show_bug.cgi?id=24912
        mountx(list->arg, dst, "bind", MS_BIND | (list->read_only ? 0 : MS_REC), NULL);
        if (list->read_only)
            mountx(list->arg, dst, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY, NULL);
        free(dst);
    }
}

static void bind_list_free(struct bind_list *list) {
    while (list) {
        struct bind_list *next = list->next;
        free(list);
        list = next;
    }
}

static const char *const systemd_bus_name = "org.freedesktop.systemd1";
static const char *const systemd_path_name = "/org/freedesktop/systemd1";
static const char *const manager_interface = "org.freedesktop.systemd1.Manager";

static void wait_for_unit(pid_t child_pid, const char *expected_name) {
    for (;;) {
        char *unit;
        check(sd_pid_get_unit(child_pid, &unit));
        bool equal = !strcmp(expected_name, unit);
        free(unit);
        if (equal) break;
    }
}

static void start_scope_unit(sd_bus *connection, pid_t child_pid, long memory_limit,
                             long tasks_max, long cpu_shares, char *devices,
                             const char *unit_name) {
    sd_bus_message *message = NULL;
    check(sd_bus_message_new_method_call(connection, &message, systemd_bus_name, systemd_path_name,
                                         manager_interface, "StartTransientUnit"));

    check(sd_bus_message_append(message, "ss", unit_name, "fail"));
    check(sd_bus_message_open_container(message, 'a', "(sv)"));
    check(sd_bus_message_append(message, "(sv)", "PIDs", "au", 1, child_pid));
    check(sd_bus_message_append(message, "(sv)", "Description", "s",
                                "Playpen application sandbox"));
    check(sd_bus_message_append(message, "(sv)", "MemoryLimit", "t",
                                1024ULL * 1024ULL * (unsigned long long)memory_limit));
    check(sd_bus_message_append(message, "(sv)", "TasksMax", "t", (unsigned long long)tasks_max));
    check(sd_bus_message_append(message, "(sv)", "TimeoutStopUSec", "t", 1000ull));
    check(sd_bus_message_append(message, "(sv)", "DevicePolicy", "s", "strict"));

    if (devices) {
        check(sd_bus_message_open_container(message, 'r', "sv"));
        check(sd_bus_message_append(message, "s", "DeviceAllow"));
        check(sd_bus_message_open_container(message, 'v', "a(ss)"));
        check(sd_bus_message_open_container(message, 'a', "(ss)"));

        for (char *s_ptr = devices, *saveptr; ; s_ptr = NULL) {
            const char *device = strtok_r(s_ptr, ",", &saveptr);
            if (!device) break;
            char *split = strchr(device, ':');
            if (!split) errx(EXIT_FAILURE, "invalid device parameter `%s`", device);
            *split = '\0';
            sd_bus_message_append(message, "(ss)", device, split + 1);
        }

        check(sd_bus_message_close_container(message));
        check(sd_bus_message_close_container(message));
        check(sd_bus_message_close_container(message));
    }

    check(sd_bus_message_append(message, "(sv)", "CPUAccounting", "b", 1));
    check(sd_bus_message_append(message, "(sv)", "CPUShares", "t", (unsigned long long)cpu_shares));
    check(sd_bus_message_append(message, "(sv)", "BlockIOAccounting", "b", 1));
    check(sd_bus_message_close_container(message));
    check(sd_bus_message_append(message, "a(sa(sv))", 0));

    sd_bus_error error = SD_BUS_ERROR_NULL;
    int rc = sd_bus_call(connection, message, 0, &error, NULL);
    if (rc < 0) errx(EXIT_FAILURE, "%s",
                     sd_bus_error_is_set(&error) ? error.message : strerror(-rc));
    sd_bus_message_unref(message);

    wait_for_unit(child_pid, unit_name);
}

static void stop_scope_unit(sd_bus *connection, const char *unit_name) {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int rc = sd_bus_call_method(connection, systemd_bus_name, systemd_path_name, manager_interface,
                                "StopUnit", &error, NULL, "ss", unit_name, "fail");
    if (rc < 0) {
        if (sd_bus_error_is_set(&error)) {
            // NoSuchUnit errors are expected as the contained processes can die at any point.
            if (strcmp(error.name, "org.freedesktop.systemd1.NoSuchUnit"))
                errx(EXIT_FAILURE, "%s", error.message);
            sd_bus_error_free(&error);
        } else
            errx(EXIT_FAILURE, "%s", strerror(-rc));
    }
}

static void epoll_add(int epoll_fd, int fd, uint32_t events) {
    struct epoll_event event = { .data.fd = fd, .events = events };
    check_posix(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event), "epoll_ctl");
}

static void copy_to_stdstream(int in_fd, int out_fd) {
    uint8_t buffer[BUFSIZ];
    ssize_t n = read(in_fd, buffer, sizeof(buffer));
    if (check_eagain(n, "read")) return;
    check_posix(write(out_fd, buffer, (size_t)n), "write");
}

static int get_syscall_nr(const char *name) {
    int result = seccomp_syscall_resolve_name(name);
    if (result == __NR_SCMP_ERROR) {
        errx(EXIT_FAILURE, "non-existent syscall: %s", name);
    }
    return result;
}

_Noreturn static void usage(FILE *out) {
    fprintf(out, "usage: %s [options] [root] [command ...]\n", program_invocation_short_name);
    fputs("Options:\n"
          " -h, --help                  display this help\n"
          " -v, --version               display version\n"
          " -p, --mount-proc            mount /proc in the container\n"
          " -D, --mount-dev             mount /dev as devtmpfs in the container\n"
          " -b, --bind                  bind mount a read-only directory in the container\n"
          " -B, --bind-rw               bind mount a directory in the container\n"
          " -u, --user=USER             the user to run the program as\n"
          " -n, --hostname=NAME         the hostname to set the container to\n"
          " -t, --timeout=INTEGER       how long the container is allowed to run\n"
          " -m, --memory-limit=LIMIT    the memory limit of the container\n"
          " -T, --tasks-max=LIMIT       max number of tasks in the sandbox (default: 32)\n"
          " -C, --cpu-shares=SHARES     CPU time shares, from 2 to 262144 (default: 1024)\n"
          " -d, --devices=LIST          comma-separated whitelist of devices\n"
          " -s, --syscalls=LIST         semicolon-separated whitelist of syscalls\n"
          " -S, --syscalls-file=PATH    whitelist file containing one syscall name per line\n"
          " -l, --learn                 append missing rules to the system call whitelist\n"
          " -L, --learn-coarse          coarser learning mode without parameter checks\n",
          out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

static void set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    check_posix(flags, "fcntl");
    check_posix(fcntl(fd, F_SETFL, flags | O_NONBLOCK), "fcntl");
}

// Mark any extra file descriptors `CLOEXEC`. Only `stdin`, `stdout` and `stderr` are left open.
static void prevent_leaked_file_descriptors() {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) err(EXIT_FAILURE, "opendir");
    struct dirent *dp;
    while ((dp = readdir(dir))) {
        char *end;
        int fd = (int)strtol(dp->d_name, &end, 10);
        if (*end == '\0' && fd > 2 && fd != dirfd(dir)) {
            check_posix(ioctl(fd, FIOCLEX), "ioctl");
        }
    }
    closedir(dir);
}

static long strtolx_positive(const char *s, const char *what) {
    char *end;
    errno = 0;
    long result = strtol(s, &end, 10);
    if (errno) errx(EXIT_FAILURE, "%s is too large", what);
    if (*end != '\0' || result < 0)
        errx(EXIT_FAILURE, "%s must be a positive integer", what);
    return result;
}

#ifdef __x86_64__
static const int arg_registers[] = {RDI, RSI, RDX, R10, R8, R9};
#else
static const int arg_registers[] = {EBX, ECX, EDX, ESI, EDI, EBP};
#endif

static long get_parameter(pid_t pid, unsigned index) {
    if (index < 1 || index > sizeof(arg_registers) / sizeof(arg_registers[0])) {
        errx(EXIT_FAILURE, "parameter index invalid");
    }
    return ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * (size_t)arg_registers[index - 1]);
}

static void do_trace(pid_t pid, int status, enum learn learn, FILE *whitelist) {
    int inject_signal = 0;
    if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_SECCOMP << 8)) {
        errno = 0;
#ifdef __x86_64__
        long syscall = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX);
#else
        long syscall = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_EAX);
#endif
        if (errno) err(EXIT_FAILURE, "ptrace");
        char *rule = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)syscall);
        if (!rule) errx(EXIT_FAILURE, "seccomp_syscall_resolve_num_arch");

        struct {
            const char *name;
            unsigned count, p1, p2;
        } calls[] = {
            {"fadvise64",    1, 4, 0},
            {"fadvise64_64", 1, 2, 0},
            {"fcntl",        1, 2, 0},
            {"futex",        1, 2, 0},
            {"getsockopt",   2, 2, 3},
            {"ioctl",        1, 2, 0},
            {"madvise",      1, 3, 0},
            {"prctl",        1, 1, 0},
            {"setsockopt",   2, 2, 3}
        };

        if (learn == LEARN_FINE) {
            for (size_t i = 0; i < sizeof(calls) / sizeof(calls[0]); i++) {
                if (!strcmp(rule, calls[i].name)) {
                    free(rule);
                    long value = get_parameter(pid, calls[i].p1);
                    if (calls[i].count == 1) {
                        asprintfx(&rule, "%s: %u == %ld", calls[i].name, calls[i].p1, value);
                    } else {
                        long value2 = get_parameter(pid, calls[i].p2);
                        asprintfx(&rule, "%s: %u == %ld, %u == %ld", calls[i].name, calls[i].p1,
                                  value, calls[i].p2, value2);
                    }
                    break;
                }
            }
        }

        rewind(whitelist);
        char *line = NULL;
        size_t len = 0;
        ssize_t n_read;
        while ((n_read = getline(&line, &len, whitelist)) != -1) {
            if (line[n_read - 1] == '\n') line[n_read - 1] = '\0';
            if (!strcmp(rule, line)) {
                rule = NULL;
                break;
            }
        }
        if (ferror(whitelist)) {
            err(EXIT_FAILURE, "getline");
        }
        free(line);

        if (rule) {
            fprintf(whitelist, "%s\n", rule);
            free(rule);
        }
    } else if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_CLONE << 8)) {
        // new child
    } else if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_FORK << 8)) {
        // new child
    } else if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_VFORK << 8)) {
        // new child
    } else if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_STOP << 8)) {
        // attached child
    } else if ((status >> 8) == (SIGSTOP | PTRACE_EVENT_STOP << 8)) {
        // group stop
    } else {
        inject_signal = WSTOPSIG(status);
    }
    check_posix(ptrace(PTRACE_CONT, pid, 0, inject_signal), "ptrace");
}

static void handle_signal(pid_t main_pid, int sig_fd, sd_bus *connection, const char *unit_name,
                          enum learn learn, FILE *whitelist) {
    struct signalfd_siginfo si;
    ssize_t bytes_r = read(sig_fd, &si, sizeof(si));
    check_posix(bytes_r, "read");

    if (bytes_r != sizeof(si))
        errx(EXIT_FAILURE, "read the wrong amount of bytes");

    switch (si.ssi_signo) {
    case SIGHUP:
    case SIGINT:
    case SIGTERM:
        stop_scope_unit(connection, unit_name);
        errx(EXIT_FAILURE, "interrupted, stopping early");
    }

    if (si.ssi_signo != SIGCHLD)
        errx(EXIT_FAILURE, "got an unexpected signal");

    // handle coalesced signals
    pid_t pid;
    int status;
    while ((pid = waitpid(-1, &status, WNOHANG|__WALL))) {
        check_posix(pid, "waitpid");
        if (WIFSTOPPED(status)) {
            do_trace(pid, status, learn, whitelist);
        } else if (WIFSIGNALED(status)) {
            errx(EXIT_FAILURE, "application terminated abnormally with signal %d (%s)",
                 WTERMSIG(status), strsignal(WTERMSIG(status)));
        } else if (WIFEXITED(status) && pid == main_pid) {
            if (WEXITSTATUS(status)) {
                warnx("application terminated with error code %d", si.ssi_status);
            }
            exit(WEXITSTATUS(status));
        }
    }
}

static struct scmp_arg_cmp parse_parameter_check(const char *arg) {
    char *end;
    errno = 0;
    long index = strtol(arg, &end, 10);
    if (errno || index < 1 || (size_t)index > sizeof(arg_registers) / sizeof(arg_registers[0])) {
        errx(EXIT_FAILURE, "invalid system call whitelist: invalid parameter index");
    }
    index--;

    // skip whitespace
    char *cursor = end + strspn(end, " \t");

    enum scmp_compare op;
    if (!strncmp(cursor, "!=", 2)) {
        op = SCMP_CMP_NE;
        cursor += 2;
    } else if (!strncmp(cursor, "<", 1)) {
        op = SCMP_CMP_LT;
        cursor += 1;
    } else if (!strncmp(cursor, "<=", 2)) {
        op = SCMP_CMP_LE;
        cursor += 2;
    } else if (!strncmp(cursor, "==", 2)) {
        op = SCMP_CMP_EQ;
        cursor += 2;
    } else if (!strncmp(cursor, ">=", 2)) {
        op = SCMP_CMP_GE;
        cursor += 2;
    } else if (!strncmp(cursor, ">", 1)) {
        op = SCMP_CMP_GT;
        cursor += 1;
    } else {
        errx(EXIT_FAILURE, "invalid system call whitelist operator: %s", cursor);
    }

    errno = 0;
    long value = strtol(cursor, &end, 10);
    if (errno) {
        errx(EXIT_FAILURE, "invalid system call whitelist: invalid parameter value");
    }

    // check for trailing garbage
    if (*(end + strspn(end, " \t")) != '\0') {
        errx(EXIT_FAILURE, "invalid system call whitelist: invalid parameter rule");
    }

    return SCMP_CMP(index, op, (unsigned long)value);
}

static struct scmp_arg_cmp *parse_parameter_checks(char *s, unsigned *count) {
    struct scmp_arg_cmp *args = NULL;
    unsigned n_args = 0;
    for (char *s_ptr = s, *saveptr;; s_ptr = NULL) {
        char *arg = strtok_r(s_ptr, ",", &saveptr);
        if (!arg) break;
        n_args++;
        if (n_args > 10000) {
            errx(EXIT_FAILURE, "too many parameter checks");
        }
        args = realloc(args, n_args * sizeof(struct scmp_arg_cmp));
        if (!args) {
            err(EXIT_FAILURE, "realloc");
        }
        args[n_args - 1] = parse_parameter_check(arg);
    }
    *count = n_args;
    if (!n_args) {
        errx(EXIT_FAILURE, "invalid system call whitelist: colon not followed by arguments");
    }
    return args;
}

static void handle_seccomp_rule(scmp_filter_ctx ctx, char *rule) {
    char *split = strchr(rule, ':');
    struct scmp_arg_cmp *args = NULL;
    unsigned n_args = 0;
    if (split) {
        *split = '\0';
        args = parse_parameter_checks(split + 1, &n_args);
    }
    check(seccomp_rule_add_array(ctx, SCMP_ACT_ALLOW, get_syscall_nr(rule), n_args, args));
    free(args);
}

int main(int argc, char **argv) {
    prevent_leaked_file_descriptors();

    bool mount_proc = false;
    bool mount_dev = false;
    const char *username = "nobody";
    const char *hostname = "playpen";
    long timeout = 0;
    long memory_limit = 128;
    long tasks_max = 32;
    long cpu_shares = 1024;
    struct bind_list *binds = NULL, *binds_tail = NULL;
    char *devices = NULL;
    char *syscalls = NULL;
    const char *syscalls_file = NULL;
    enum learn learn = LEARN_NONE;

    static const struct option opts[] = {
        { "help",          no_argument,       NULL, 'h' },
        { "version",       no_argument,       NULL, 'v' },
        { "mount-proc",    no_argument,       NULL, 'p' },
        { "mount-dev",     no_argument,       NULL, 'D' },
        { "bind",          required_argument, NULL, 'b' },
        { "bind-rw",       required_argument, NULL, 'B' },
        { "user",          required_argument, NULL, 'u' },
        { "hostname",      required_argument, NULL, 'n' },
        { "timeout",       required_argument, NULL, 't' },
        { "memory-limit",  required_argument, NULL, 'm' },
        { "tasks-max",     required_argument, NULL, 'T' },
        { "cpu-shares",    required_argument, NULL, 'C' },
        { "devices",       required_argument, NULL, 'd' },
        { "syscalls",      required_argument, NULL, 's' },
        { "syscalls-file", required_argument, NULL, 'S' },
        { "learn",         no_argument,       NULL, 'l' },
        { "learn-coarse",  no_argument,       NULL, 'L' },
        { NULL, 0, NULL, 0 }
    };

    for (;;) {
        int opt = getopt_long(argc, argv, "hvpDb:B:u:n:t:m:T:C:d:s:S:lL", opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'h':
            usage(stdout);
        case 'v':
            printf("%s %s\n", program_invocation_short_name, VERSION);
            return 0;
        case 'p':
            mount_proc = true;
            break;
        case 'D':
            mount_dev = true;
            break;
        case 'b':
        case 'B':
            if (binds) {
                binds_tail->next = bind_list_alloc(optarg, opt == 'b');
                binds_tail = binds_tail->next;
            } else {
                binds = binds_tail = bind_list_alloc(optarg, opt == 'b');
            }
            break;
        case 'u':
            username = optarg;
            break;
        case 'n':
            hostname = optarg;
            break;
        case 't':
            timeout = strtolx_positive(optarg, "timeout");
            break;
        case 'm':
            memory_limit = strtolx_positive(optarg, "memory limit");
            break;
        case 'T':
            tasks_max = strtolx_positive(optarg, "tasks limit");
            break;
        case 'C':
            cpu_shares = strtolx_positive(optarg, "CPU shares");
            break;
        case 'd':
            devices = optarg;
            break;
        case 's':
            syscalls = optarg;
            break;
        case 'S':
            syscalls_file = optarg;
            break;
        case 'l':
            learn = LEARN_FINE;
            break;
        case 'L':
            learn = LEARN_COARSE;
            break;
        default:
            usage(stderr);
        }
    }

    if (learn != LEARN_NONE && !syscalls_file) {
        errx(EXIT_FAILURE, "learning mode requires specifying a system call whitelist");
    }

    if (argc - optind < 2) {
        usage(stderr);
    }

    const char *root = argv[optind];
    optind++;

    scmp_filter_ctx ctx = seccomp_init(learn != LEARN_NONE ? SCMP_ACT_TRACE(0) : SCMP_ACT_KILL);
    if (!ctx) errx(EXIT_FAILURE, "seccomp_init");

    FILE *whitelist = NULL;
    if (syscalls_file) {
        whitelist = fopen(syscalls_file, learn != LEARN_NONE ? "a+e" : "re");
        if (!whitelist) err(EXIT_FAILURE, "failed to open syscalls file: %s", syscalls_file);
        char *line = NULL;
        size_t len = 0;
        ssize_t n_read;
        while ((n_read = getline(&line, &len, whitelist)) != -1) {
            if (line[n_read - 1] == '\n') line[n_read - 1] = '\0';
            handle_seccomp_rule(ctx, line);
        }
        if (ferror(whitelist)) {
            err(EXIT_FAILURE, "getline");
        }
        free(line);
        if (learn == LEARN_NONE) {
            fclose(whitelist);
            whitelist = NULL;
        }
    }

    check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_execve, 0));

    if (syscalls) {
        for (char *s_ptr = syscalls, *saveptr; ; s_ptr = NULL) {
            char *rule = strtok_r(s_ptr, ";", &saveptr);
            if (!rule) break;
            handle_seccomp_rule(ctx, rule);
        }
    }

    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    check_posix(epoll_fd, "epoll_create1");

    sigset_t mask, old_mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    check_posix(sigprocmask(SIG_BLOCK, &mask, &old_mask), "sigprocmask");

    int sig_fd = signalfd(-1, &mask, SFD_CLOEXEC);
    check_posix(sig_fd, "signalfd");

    epoll_add(epoll_fd, sig_fd, EPOLLIN);

    int pipe_in[2];
    int pipe_out[2];
    int pipe_err[2];
    check_posix(pipe(pipe_in), "pipe");
    check_posix(pipe(pipe_out), "pipe");
    set_non_blocking(pipe_out[0]);
    check_posix(pipe(pipe_err), "pipe");
    set_non_blocking(pipe_err[0]);

    int rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO,
                       &(struct epoll_event){ .data.fd = STDIN_FILENO, .events = EPOLLIN });
    if (rc == -1 && errno != EPERM) err(EXIT_FAILURE, "epoll_ctl");
    const bool stdin_non_epoll = rc == -1;

    epoll_add(epoll_fd, pipe_out[0], EPOLLIN);
    epoll_add(epoll_fd, pipe_err[0], EPOLLIN);
    epoll_add(epoll_fd, pipe_in[1], EPOLLET | EPOLLOUT);

    unsigned long flags = SIGCHLD|CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS|CLONE_NEWNET;
    pid_t pid = (pid_t)syscall(__NR_clone, flags, NULL);
    check_posix(pid, "clone");

    if (pid == 0) {
        dup2(pipe_in[0], STDIN_FILENO);
        close(pipe_in[0]);
        close(pipe_in[1]);

        dup2(pipe_out[1], STDOUT_FILENO);
        close(pipe_out[0]);
        close(pipe_out[1]);

        dup2(pipe_err[1], STDERR_FILENO);
        close(pipe_err[0]);
        close(pipe_err[1]);

        // Kill this process if the parent dies.
        check_posix(prctl(PR_SET_PDEATHSIG, SIGKILL), "prctl");

        // Wait until the scope unit is set up before moving on. This also ensures that the parent
        // didn't die before `prctl` was called.
        uint8_t ready;
        check_posix(read(STDIN_FILENO, &ready, sizeof(ready)), "read");

        check_posix(sethostname(hostname, strlen(hostname)), "sethostname");

        // avoid propagating mounts to or from the parent's mount namespace
        mountx(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL);

        // turn directory into a bind mount
        mountx(root, root, "bind", MS_BIND|MS_REC, NULL);

        // re-mount as read-only
        mountx(root, root, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC, NULL);

        if (mount_proc) {
            char *mnt = join_path(root, "proc");
            mountx(NULL, mnt, "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
            free(mnt);
        }

        if (mount_dev) {
            char *mnt = join_path(root, "dev");
            mountx(NULL, mnt, "devtmpfs", MS_NOSUID|MS_NOEXEC, NULL);
            free(mnt);
        }

        char *shm = join_path(root, "dev/shm");
        if (mount(NULL, shm, "tmpfs", MS_NOSUID|MS_NODEV, NULL) == -1) {
            if (errno != ENOENT) {
                err(EXIT_FAILURE, "mounting /dev/shm failed");
            }
        }
        free(shm);

        char *tmp = join_path(root, "tmp");
        if (mount(NULL, tmp, "tmpfs", MS_NOSUID|MS_NODEV, NULL) == -1) {
            if (errno != ENOENT) {
                err(EXIT_FAILURE, "mounting /tmp failed");
            }
        }
        free(tmp);

        bind_list_apply(root, binds);

        // preserve a reference to the target directory
        check_posix(chdir(root), "chdir");

        // make the working directory into the root of the mount namespace
        mountx(".", "/", NULL, MS_MOVE, NULL);

        // chroot into the root of the mount namespace
        check_posix(chroot("."), "chroot into `%s` failed", root);
        check_posix(chdir("/"), "entering chroot `%s` failed", root);

        errno = 0;
        struct passwd *pw = getpwnam(username);
        if (!pw) {
            if (errno) {
                err(EXIT_FAILURE, "getpwnam");
            } else {
                errx(EXIT_FAILURE, "no passwd entry for username %s", username);
            }
        }

        mountx(NULL, pw->pw_dir, "tmpfs", MS_NOSUID|MS_NODEV, NULL);

        // switch to the user's home directory as a login shell would
        check_posix(chdir(pw->pw_dir), "chdir");

        // create a new session
        check_posix(setsid(), "setsid");

        check_posix(initgroups(username, pw->pw_gid), "initgroups");
        check_posix(setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid), "setresgid");
        check_posix(setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid), "setresuid");

        check_posix(sigprocmask(SIG_SETMASK, &old_mask, NULL), "sigprocmask");

        char path[] = "PATH=/usr/local/bin:/usr/bin:/bin";
        char *env[] = {path, NULL, NULL, NULL, NULL};
        asprintfx(env + 1, "HOME=%s", pw->pw_dir);
        asprintfx(env + 2, "USER=%s", username);
        asprintfx(env + 3, "LOGNAME=%s", username);

        check(seccomp_load(ctx));
        check_posix(execvpe(argv[optind], argv + optind, env), "execvpe");
    }

    bind_list_free(binds);
    seccomp_release(ctx);

    if (learn != LEARN_NONE) {
        long trace_flags = PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_O_TRACESECCOMP|PTRACE_O_TRACEVFORK;
        check_posix(ptrace(PTRACE_SEIZE, pid, NULL, trace_flags), "ptrace");
    }

    sd_bus *connection;
    check(sd_bus_open_system(&connection));

    char unit_name[100];
    snprintf(unit_name, sizeof(unit_name), "playpen-%u.scope", getpid());

    start_scope_unit(connection, pid, memory_limit, tasks_max, cpu_shares, devices, unit_name);

    // Inform the child that the scope unit has been created.
    check_posix(write(pipe_in[1], &(uint8_t) { 0 }, 1), "write");
    set_non_blocking(pipe_in[1]);

    int timer_fd = -1;
    if (timeout) {
        timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
        check_posix(timer_fd, "timerfd_create");
        epoll_add(epoll_fd, timer_fd, EPOLLIN);

        struct itimerspec spec = { .it_value = { .tv_sec = timeout } };
        check_posix(timerfd_settime(timer_fd, 0, &spec, NULL), "timerfd_settime");
    }

    uint8_t stdin_buffer[PIPE_BUF];
    ssize_t stdin_bytes_read = 0;

    for (;;) {
        struct epoll_event events[8];
        int n_event = epoll_wait(epoll_fd, events, sizeof(events) / sizeof(events[0]), -1);

        if (n_event < 0) {
            if (errno == EINTR)
                continue;
            err(EXIT_FAILURE, "epoll_wait");
        }

        for (int i = 0; i < n_event; ++i) {
            struct epoll_event *evt = &events[i];

            if (evt->events & EPOLLERR) {
                close(evt->data.fd);
                continue;
            }

            if (evt->events & EPOLLIN) {
                if (evt->data.fd == timer_fd) {
                    warnx("timeout triggered!");
                    stop_scope_unit(connection, unit_name);
                    return EXIT_FAILURE;
                } else if (evt->data.fd == sig_fd) {
                    handle_signal(pid, sig_fd, connection, unit_name, learn, whitelist);
                } else if (evt->data.fd == pipe_out[0]) {
                    copy_to_stdstream(pipe_out[0], STDOUT_FILENO);
                } else if (evt->data.fd == pipe_err[0]) {
                    copy_to_stdstream(pipe_err[0], STDERR_FILENO);
                } else if (evt->data.fd == STDIN_FILENO) {
                    stdin_bytes_read = read(STDIN_FILENO, stdin_buffer, sizeof(stdin_buffer));
                    check_posix(stdin_bytes_read, "read");
                    if (stdin_bytes_read == 0) {
                        check_posix(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL),
                                    "epoll_ctl");
                        close(STDIN_FILENO);
                        close(pipe_in[1]);
                        continue;
                    }
                    ssize_t bytes_written = write(pipe_in[1], stdin_buffer, (size_t)stdin_bytes_read);
                    if (check_eagain(bytes_written, "write")) {
                        check_posix(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL),
                                    "epoll_ctl");
                        continue;
                    }
                    stdin_bytes_read = 0;
                    continue;
                }
            }

            // the child process is ready for more input
            if (evt->events & EPOLLOUT && evt->data.fd == pipe_in[1]) {
                // deal with previously buffered data
                if (stdin_bytes_read > 0) {
                    ssize_t bytes_written = write(pipe_in[1], stdin_buffer, (size_t)stdin_bytes_read);
                    if (check_eagain(bytes_written, "write")) continue;
                    stdin_bytes_read = 0;

                    if (!stdin_non_epoll) {
                        epoll_add(epoll_fd, STDIN_FILENO, EPOLLIN); // accept more data
                    }
                }

                if (stdin_non_epoll) {
                    // drain stdin until a write would block
                    for (;;) {
                        stdin_bytes_read = read(STDIN_FILENO, stdin_buffer, sizeof(stdin_buffer));
                        check_posix(stdin_bytes_read, "read");
                        ssize_t bytes_written = write(pipe_in[1], stdin_buffer,
                                                      (size_t)stdin_bytes_read);
                        if (check_eagain(bytes_written, "write")) break;

                        if (stdin_bytes_read < (ssize_t)sizeof(stdin_buffer)) {
                            close(STDIN_FILENO);
                            close(pipe_in[1]);
                            break;
                        }
                    }
                    continue;
                }
            }

            if (evt->events & EPOLLHUP) {
                if (evt->data.fd == STDIN_FILENO) {
                    close(pipe_in[1]);
                    check_posix(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL),
                                "epoll_ctl");
                }
                close(evt->data.fd);
            }
        }
    }
}
