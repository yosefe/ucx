/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2014.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "debug_int.h"
#include "debug.h"
#include "log.h"

#include <ucs/debug/backtrace/base/backtrace.h>
#include <ucs/datastruct/khash.h>
#include <ucs/profile/profile.h>
#include <ucs/sys/checker.h>
#include <ucs/sys/string.h>
#include <ucs/sys/sys.h>
#include <ucs/type/spinlock.h>
#include <sys/wait.h>
#include <link.h>
#include <dirent.h>


#define UCS_GDB_MAX_ARGS 32

KHASH_MAP_INIT_INT(ucs_signal_orig_action, struct sigaction*);


#define UCS_SYS_SIGNAME(signame) [SIG ## signame] = #signame
const char *ucs_signal_names[] = {
    [0] = "SIGNAL0",
    UCS_SYS_SIGNAME(HUP),
    UCS_SYS_SIGNAME(INT),
    UCS_SYS_SIGNAME(QUIT),
    UCS_SYS_SIGNAME(ILL),
    UCS_SYS_SIGNAME(TRAP),
    UCS_SYS_SIGNAME(ABRT),
    UCS_SYS_SIGNAME(BUS),
    UCS_SYS_SIGNAME(FPE),
    UCS_SYS_SIGNAME(KILL),
    UCS_SYS_SIGNAME(USR1),
    UCS_SYS_SIGNAME(SEGV),
    UCS_SYS_SIGNAME(USR2),
    UCS_SYS_SIGNAME(PIPE),
    UCS_SYS_SIGNAME(ALRM),
    UCS_SYS_SIGNAME(TERM),
#ifdef SIGSTKFLT
    UCS_SYS_SIGNAME(STKFLT),
#endif
    UCS_SYS_SIGNAME(CHLD),
    UCS_SYS_SIGNAME(CONT),
    UCS_SYS_SIGNAME(STOP),
    UCS_SYS_SIGNAME(TSTP),
    UCS_SYS_SIGNAME(TTIN),
    UCS_SYS_SIGNAME(TTOU),
    UCS_SYS_SIGNAME(URG),
    UCS_SYS_SIGNAME(XCPU),
    UCS_SYS_SIGNAME(XFSZ),
    UCS_SYS_SIGNAME(VTALRM),
    UCS_SYS_SIGNAME(PROF),
    UCS_SYS_SIGNAME(WINCH),
    UCS_SYS_SIGNAME(IO),
#ifdef SIGPWR
    UCS_SYS_SIGNAME(PWR),
#endif
    UCS_SYS_SIGNAME(SYS),
#if defined __linux__
    [SIGSYS + 1] = NULL
#elif defined __FreeBSD__
    [SIGRTMIN] = NULL
#else
#error "Port me"
#endif
};


static stack_t  ucs_debug_signal_stack    = {NULL, 0, 0};

static khash_t(ucs_signal_orig_action) ucs_signal_orig_action_map;

static ucs_recursive_spinlock_t ucs_kh_lock;

static int ucs_debug_initialized = 0;


static int orig_sigaction(int signum, const struct sigaction *act,
                          struct sigaction *oact);


static char *ucs_debug_strdup(const char *str)
{
    size_t length;
    char *newstr;

    length = strlen(str) + 1;
    newstr = ucs_sys_realloc(NULL, 0, length);
    if (newstr != NULL) {
        strncpy(newstr, str, length);
    }
    return newstr;
}

static void ucs_debugger_attach()
{
    static const char *vg_cmds_fmt = "file %s\n"
                                     "target remote | vgdb\n";
    static const char *bt_cmds     = "bt\n"
                                     "list\n";
    static char pid_str[16];
    char *vg_cmds;
    char *gdb_cmdline;
    char gdb_commands_file[256];
    char* argv[6 + UCS_GDB_MAX_ARGS];
    pid_t pid, debug_pid;
    int fd, ret, narg;
    char UCS_V_UNUSED *self_exe;

    /* Fork a process which will execute gdb and attach to the current process.
     * We must avoid trigerring calls to malloc/free, since the heap may be corrupted.
     * Therefore all allocations are done with mmap() or use static arrays.
     */

    debug_pid = getpid();

    pid = fork();
    if (pid < 0) {
        ucs_log_fatal_error("fork returned %d: %m", pid);
        return;
    }

    /* retrieve values from original process, before forking */
    self_exe = ucs_debug_strdup(ucs_get_exe());

    if (pid == 0) {
        gdb_cmdline = ucs_debug_strdup(ucs_global_opts.gdb_command);
        narg = 0;
        argv[narg] = strtok(gdb_cmdline, " \t");
        while (argv[narg] != NULL) {
            ++narg;
            argv[narg] = strtok(NULL, " \t");
        }

        /* Make coverity know that argv[0] will not be affected by TMPDIR */
        if (narg == 0) {
            return;
        }

        if (!RUNNING_ON_VALGRIND) {
            snprintf(pid_str, sizeof(pid_str), "%d", debug_pid);
            argv[narg++] = "-p";
            argv[narg++] = pid_str;
        }

        /* Generate a file name for gdb commands */
        memset(gdb_commands_file, 0, sizeof(gdb_commands_file));
        snprintf(gdb_commands_file, sizeof(gdb_commands_file) - 1,
                 "%s/.gdbcommands.uid-%d", ucs_get_tmpdir(), geteuid());

        /* Write gdb commands and add the file to argv is successful */
        fd = open(gdb_commands_file, O_WRONLY|O_TRUNC|O_CREAT, 0600);
        if (fd >= 0) {
            if (RUNNING_ON_VALGRIND) {
                vg_cmds = ucs_sys_realloc(NULL, 0, strlen(vg_cmds_fmt) + strlen(self_exe));
                sprintf(vg_cmds, vg_cmds_fmt, self_exe);
                if (write(fd, vg_cmds, strlen(vg_cmds)) != strlen(vg_cmds)) {
                    ucs_log_fatal_error("Unable to write to command file: %m");
                }
            }

            if (ucs_global_opts.handle_errors & UCS_BIT(UCS_HANDLE_ERROR_BACKTRACE)) {
                if (write(fd, bt_cmds, strlen(bt_cmds)) != strlen(bt_cmds)) {
                    ucs_log_fatal_error("Unable to write to command file: %m");
                }
            }
            close(fd);

            argv[narg++] = "-x";
            argv[narg++] = gdb_commands_file;
        } else {
            ucs_log_fatal_error("Unable to open '%s' for writing: %m",
                                gdb_commands_file);
        }

        argv[narg++] = NULL;

        /* Execute GDB */
        /* coverity[tainted_string] */
        ret = execvp(argv[0], argv);
        if (ret < 0) {
            ucs_log_fatal_error("Failed to execute %s: %m", argv[0]);
            exit(-1);
        }
    }

    waitpid(pid, &ret, 0);
}

static void UCS_F_NOINLINE ucs_debug_freeze()
{
    static volatile int freeze = 1;
    while (freeze) {
        pause();
    }
}

static void ucs_debug_stop_handler(int signo)
{
    ucs_debug_freeze();
}

static ucs_status_t ucs_debug_enum_threads_cb(pid_t tid, void *ctx)
{
    int ret;

    if ((tid != 0) && (tid != ucs_get_tid())) {
        ret = ucs_tgkill(getpid(), tid, SIGUSR1);
        if (ret < 0) {
            return UCS_ERR_NO_MESSAGE;
        }
    }

    return UCS_OK;
}

static void ucs_debug_stop_other_threads()
{
    signal(SIGUSR1, ucs_debug_stop_handler);
    ucs_sys_enum_threads(ucs_debug_enum_threads_cb, NULL);
}

static void ucs_debug_send_mail(const char *message)
{
    FILE *stream;

    if (!strlen(ucs_global_opts.error_mail_to)) {
        return;
    }

    stream = popen("/usr/lib/sendmail -t", "w");
    if (stream == NULL) {
        return;
    }

    fprintf(stdout, "Sending notification to %s\n", ucs_global_opts.error_mail_to);
    fflush(stdout);

    fprintf(stream, "To:           %s\n", ucs_global_opts.error_mail_to);
    fprintf(stream, "From:         %s\n", "ucx@openucx.org");
    fprintf(stream, "Subject:      ucx error report on %s\n",
            ucs_get_host_name());
    fprintf(stream, "Content-Type: text/plain\n");
    fprintf(stream, "\n");

    fprintf(stream, "program: %s\n", ucs_get_exe());
    fprintf(stream, "hostname: %s\n", ucs_get_host_name());
    fprintf(stream, "process id: %d\n", getpid());
    fprintf(stream, "\n");

    fprintf(stream, "\n");
    fprintf(stream, "%s\n", message);
    fprintf(stream, "\n");

    ucs_debug_print_backtrace(stream, 2,
                              UCS_DEBUG_BACKTRACE_PRINT_FLAG_SHOW_SOURCE);

    if (strlen(ucs_global_opts.error_mail_footer)) {
        fprintf(stream, "\n");
        fprintf(stream, "%s\n", ucs_global_opts.error_mail_footer);
    }
    fprintf(stream, "\n");

    pclose(stream);
}

static void ucs_error_freeze(const char *message)
{
    struct sigaction sigact = {
        .sa_handler = SIG_DFL,
        .sa_flags   = 0
    };
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    char response;
    int ret;

    /* restore original SIGINT handler to allow termitate process via Ctrl+C */
    sigemptyset(&sigact.sa_mask);
    orig_sigaction(SIGINT, &sigact, NULL);

    ucs_debug_stop_other_threads();

    if (pthread_mutex_trylock(&lock) == 0) {
        if (strlen(ucs_global_opts.gdb_command) && isatty(fileno(stdout)) &&
            isatty(fileno(stdin)))
        {
            ucs_log_fatal_error("Process frozen, press Enter to attach a debugger...");
            ret = read(fileno(stdin), &response, 1); /* Use low-level input to avoid deadlock */
            if ((ret == 1) && (response == '\n')) {
                ucs_debugger_attach();
            } else {
                ucs_debug_freeze();
            }
        } else {
            ucs_debug_send_mail(message);
            ucs_log_fatal_error("Process frozen...");
            ucs_debug_freeze();
        }

        pthread_mutex_unlock(&lock);
    } else {
        ucs_debug_freeze();
    }
}

static const char *ucs_signal_cause_common(int si_code)
{
    switch (si_code) {
    case SI_USER      : return "kill(2) or raise(3)";
    case SI_KERNEL    : return "Sent by the kernel";
    case SI_QUEUE     : return "sigqueue(2)";
    case SI_TIMER     : return "POSIX timer expired";
    case SI_MESGQ     : return "POSIX message queue state changed";
    case SI_ASYNCIO   : return "AIO completed";
#ifdef SI_SIGIO
    case SI_SIGIO     : return "queued SIGIO";
#endif
#ifdef SI_TKILL
    case SI_TKILL     : return "tkill(2) or tgkill(2)";
#endif
    default           : return "<unknown si_code>";
    }
}

static const char *ucs_signal_cause_ill(int si_code)
{
    switch (si_code) {
    case ILL_ILLOPC   : return "illegal opcode";
    case ILL_ILLOPN   : return "illegal operand";
    case ILL_ILLADR   : return "illegal addressing mode";
    case ILL_ILLTRP   : return "illegal trap";
    case ILL_PRVOPC   : return "privileged opcode";
    case ILL_PRVREG   : return "privileged register";
    case ILL_COPROC   : return "coprocessor error";
    case ILL_BADSTK   : return "internal stack error";
    default           : return ucs_signal_cause_common(si_code);
    }
}

static const char *ucs_signal_cause_fpe(int si_code)
{
    switch (si_code) {
    case FPE_INTDIV   : return "integer divide by zero";
    case FPE_INTOVF   : return "integer overflow";
    case FPE_FLTDIV   : return "floating-point divide by zero";
    case FPE_FLTOVF   : return "floating-point overflow";
    case FPE_FLTUND   : return "floating-point underflow";
    case FPE_FLTRES   : return "floating-point inexact result";
    case FPE_FLTINV   : return "floating-point invalid operation";
    case FPE_FLTSUB   : return "subscript out of range";
    default           : return ucs_signal_cause_common(si_code);
    }
}

static const char *ucs_signal_cause_segv(int si_code)
{
    switch (si_code) {
    case SEGV_MAPERR  : return "address not mapped to object";
    case SEGV_ACCERR  : return "invalid permissions for mapped object";
    default           : return ucs_signal_cause_common(si_code);
    }
}

static const char *ucs_signal_cause_bus(int si_code)
{
    switch (si_code) {
    case BUS_ADRALN   : return "invalid address alignment";
    case BUS_ADRERR   : return "nonexistent physical address";
    case BUS_OBJERR   : return "object-specific hardware error";
    default           : return ucs_signal_cause_common(si_code);
    }
}

static const char *ucs_signal_cause_trap(int si_code)
{
    switch (si_code) {
    case TRAP_BRKPT   : return "process breakpoint";
    case TRAP_TRACE   : return "process trace trap";
    default           : return ucs_signal_cause_common(si_code);
    }
}

static const char *ucs_signal_cause_cld(int si_code)
{
    switch (si_code) {
    case CLD_EXITED   : return "child has exited";
    case CLD_KILLED   : return "child was killed";
    case CLD_DUMPED   : return "child terminated abnormally";
    case CLD_TRAPPED  : return "traced child has trapped";
    case CLD_STOPPED  : return "child has stopped";
    case CLD_CONTINUED: return "stopped child has continued";
    default           : return NULL;
    }
}

static void ucs_debug_handle_error_signal(int signo, const char *cause,
                                          const char *fmt, ...)
{
    char buf[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    ucs_log_flush();
    ucs_log_fatal_error("Caught signal %d (%s: %s%s)", signo,
                        strsignal(signo), cause, buf);
    ucs_handle_error(cause);
}

static void ucs_error_signal_handler(int signo, siginfo_t *info, void *context)
{
    ucs_debug_cleanup(1);
    ucs_log_flush();

    switch (signo) {
    case SIGILL:
        ucs_debug_handle_error_signal(signo, ucs_signal_cause_ill(info->si_code), "");
        break;
    case SIGTRAP:
        ucs_debug_handle_error_signal(signo, ucs_signal_cause_trap(info->si_code), "");
        break;
    case SIGBUS:
        ucs_debug_handle_error_signal(signo, ucs_signal_cause_bus(info->si_code), "");
        break;
    case SIGFPE:
        ucs_debug_handle_error_signal(signo, ucs_signal_cause_fpe(info->si_code), "");
        break;
    case SIGSEGV:
        ucs_debug_handle_error_signal(signo, ucs_signal_cause_segv(info->si_code),
                                      " at address %p", info->si_addr);
        break;
    case SIGCHLD:
        ucs_debug_handle_error_signal(signo, ucs_signal_cause_cld(info->si_code), "");
        break;
    case SIGINT:
    case SIGTERM:
        break;
    default:
        ucs_debug_handle_error_signal(signo, ucs_signal_cause_common(info->si_code), "");
        break;
    }

    raise(signo);
}

void ucs_handle_error(const char *message)
{
    ucs_debug_cleanup(1);

    if (ucs_global_opts.handle_errors & UCS_BIT(UCS_HANDLE_ERROR_DEBUG)) {
        ucs_debugger_attach();
    } else {
        if (ucs_global_opts.handle_errors & UCS_BIT(UCS_HANDLE_ERROR_BACKTRACE)) {
            ucs_debug_print_backtrace(
                    stderr, 2, UCS_DEBUG_BACKTRACE_PRINT_FLAG_SHOW_SOURCE);
        }
        if (ucs_global_opts.handle_errors & UCS_BIT(UCS_HANDLE_ERROR_FREEZE)) {
            ucs_error_freeze(message);
        }
    }
}

int ucs_debug_is_handle_errors()
{
    static const unsigned mask = UCS_BIT(UCS_HANDLE_ERROR_BACKTRACE) |
                                 UCS_BIT(UCS_HANDLE_ERROR_FREEZE) |
                                 UCS_BIT(UCS_HANDLE_ERROR_DEBUG);
    return ucs_global_opts.handle_errors & mask;
}

static void* ucs_debug_get_orig_func(const char *symbol, void *replacement)
{
    void *func_ptr;

    func_ptr = dlsym(RTLD_NEXT, symbol);
    if (func_ptr == NULL) {
        func_ptr = dlsym(RTLD_DEFAULT, symbol);
    }
    return func_ptr;
}

#ifdef ENABLE_SIGACTION_OVERRIDE
#if !HAVE_SIGHANDLER_T
#if HAVE___SIGHANDLER_T
typedef __sighandler_t *sighandler_t;
#else
#error "Port me"
#endif
#endif

static int ucs_debug_is_error_signal(int signum)
{
    khiter_t hash_it;
    int result;

    if (!ucs_debug_is_handle_errors()) {
        return 0;
    }

    /* If this signal is error, but was disabled. */
    ucs_recursive_spin_lock(&ucs_kh_lock);
    hash_it = kh_get(ucs_signal_orig_action, &ucs_signal_orig_action_map, signum);
    result = (hash_it != kh_end(&ucs_signal_orig_action_map));
    ucs_recursive_spin_unlock(&ucs_kh_lock);
    return result;
}

sighandler_t signal(int signum, sighandler_t handler)
{
    typedef sighandler_t (*sighandler_func_t)(int, sighandler_t);

    static sighandler_func_t orig = NULL;

    if (ucs_debug_initialized && ucs_debug_is_error_signal(signum)) {
        return SIG_DFL;
    }

    if (orig == NULL) {
        orig = (sighandler_func_t)ucs_debug_get_orig_func("signal", signal);
    }

    return orig(signum, handler);
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oact)
{
    if (ucs_debug_initialized && ucs_debug_is_error_signal(signum)) {
        return orig_sigaction(signum, NULL, oact); /* Return old, do not set new */
    }

    return orig_sigaction(signum, act, oact);
}

#endif /* ENABLE_SIGACTION_OVERRIDE */

static int orig_sigaction(int signum, const struct sigaction *act,
                          struct sigaction *oact)
{
    typedef int (*sigaction_func_t)(int, const struct sigaction*, struct sigaction*);

    static sigaction_func_t orig = NULL;

    if (orig == NULL) {
        orig = (sigaction_func_t)ucs_debug_get_orig_func("sigaction", sigaction);
    }

    return orig(signum, act, oact);
}

static void ucs_debug_signal_handler(int signo)
{
    ucs_log_flush();
    ucs_global_opts.log_component.log_level = UCS_LOG_LEVEL_TRACE_DATA;
    ucs_profile_dump(ucs_profile_default_ctx);
}

static void ucs_debug_set_signal_alt_stack()
{
    int ret;

    ucs_debug_signal_stack.ss_size = SIGSTKSZ +
                                     (2 * ucs_log_get_buffer_size()) +
                                     (128 * UCS_KBYTE);
    ucs_debug_signal_stack.ss_sp =
                    ucs_sys_realloc(NULL, 0, ucs_debug_signal_stack.ss_size);
    if (ucs_debug_signal_stack.ss_sp == NULL) {
        return;
    }

    ucs_debug_signal_stack.ss_flags = 0;
    ret = sigaltstack(&ucs_debug_signal_stack, NULL);
    if (ret) {
        ucs_warn("sigaltstack(ss_sp=%p, ss_size=%zu) failed: %m",
                 ucs_debug_signal_stack.ss_sp, ucs_debug_signal_stack.ss_size);
        ucs_sys_free(ucs_debug_signal_stack.ss_sp,
                     ucs_debug_signal_stack.ss_size);
        ucs_debug_signal_stack.ss_sp = NULL;
        return;
    }

    ucs_debug("using signal stack %p size %zu", ucs_debug_signal_stack.ss_sp,
              ucs_debug_signal_stack.ss_size);
}

static inline void ucs_debug_save_original_sighandler(int signum,
                                                      const struct sigaction* orig_handler)
{
    struct sigaction *oact_copy;
    khiter_t hash_it;
    int hash_extra_status;

    ucs_recursive_spin_lock(&ucs_kh_lock);
    hash_it = kh_get(ucs_signal_orig_action, &ucs_signal_orig_action_map, signum);
    if (hash_it != kh_end(&ucs_signal_orig_action_map)) {
        goto out;
    }

    oact_copy = ucs_malloc(sizeof(*orig_handler), "orig_sighandler");
    if (oact_copy == NULL) {
        goto out;
    }

    *oact_copy = *orig_handler;
    hash_it = kh_put(ucs_signal_orig_action,
                     &ucs_signal_orig_action_map,
                     signum, &hash_extra_status);
    kh_value(&ucs_signal_orig_action_map, hash_it) = oact_copy;

out:
    ucs_recursive_spin_unlock(&ucs_kh_lock);
}

static void ucs_set_signal_handler(void (*handler)(int, siginfo_t*, void *))
{
    struct sigaction sigact, old_action;
    int i;
    int ret;

    sigact.sa_sigaction = handler;
    sigact.sa_flags     = SA_SIGINFO;
    if (ucs_debug_signal_stack.ss_sp != NULL) {
        sigact.sa_flags |= SA_ONSTACK;
    }
    sigemptyset(&sigact.sa_mask);

    for (i = 0; i < ucs_global_opts.error_signals.count; ++i) {
        ret = orig_sigaction(ucs_global_opts.error_signals.signals[i], &sigact,
                             &old_action);
        if (ret < 0) {
            ucs_warn("failed to set signal handler for sig %d : %m",
                     ucs_global_opts.error_signals.signals[i]);
        }
#if HAVE_SIGACTION_SA_RESTORER
        ucs_debug_set_sa_restorer(old_action.sa_restorer);
#endif
        ucs_debug_save_original_sighandler(
                ucs_global_opts.error_signals.signals[i], &old_action);
    }
}

void ucs_debug_init()
{
    ucs_recursive_spinlock_init(&ucs_kh_lock, 0);

    kh_init_inplace(ucs_signal_orig_action, &ucs_signal_orig_action_map);

    if (ucs_debug_is_handle_errors()) {
        ucs_debug_set_signal_alt_stack();
        ucs_set_signal_handler(ucs_error_signal_handler);
    }
    if (ucs_global_opts.debug_signo > 0) {
        struct sigaction sigact, old_action;
        memset(&sigact, 0, sizeof(sigact));
        memset(&old_action, 0, sizeof(old_action));
        sigact.sa_handler = ucs_debug_signal_handler;
        orig_sigaction(ucs_global_opts.debug_signo, &sigact, &old_action);
        ucs_debug_save_original_sighandler(ucs_global_opts.debug_signo, &old_action);
    }

    ucs_debug_backtrace_init();

    ucs_debug_initialized = 1;
}

void ucs_debug_cleanup(int on_error)
{
    struct sigaction *hndl;
    int signum;

    ucs_debug_initialized = 0;

    ucs_debug_backtrace_cleanup();

    kh_foreach_key(&ucs_signal_orig_action_map, signum,
                   ucs_debug_disable_signal(signum));

    if (!on_error) {
        kh_foreach_value(&ucs_signal_orig_action_map, hndl, ucs_free(hndl));
        kh_destroy_inplace(ucs_signal_orig_action, &ucs_signal_orig_action_map);
    }

    ucs_recursive_spinlock_destroy(&ucs_kh_lock);
}

static inline void ucs_debug_disable_signal_nolock(int signum)
{
    khiter_t hash_it;
    struct sigaction *original_action, ucs_action;
    int ret;

    hash_it = kh_get(ucs_signal_orig_action, &ucs_signal_orig_action_map,
                     signum);
    if (hash_it == kh_end(&ucs_signal_orig_action_map)) {
        ucs_warn("ucs_debug_disable_signal: signal %d was not set in ucs",
                 signum);
        return;
    }

    original_action = kh_val(&ucs_signal_orig_action_map, hash_it);
    ret = orig_sigaction(signum, original_action, &ucs_action);
    if (ret < 0) {
        ucs_warn("failed to set signal handler for sig %d : %m", signum);
    }

    kh_del(ucs_signal_orig_action, &ucs_signal_orig_action_map, hash_it);
    ucs_free(original_action);
}

void ucs_debug_disable_signal(int signum)
{
    ucs_recursive_spin_lock(&ucs_kh_lock);
    ucs_debug_disable_signal_nolock(signum);
    ucs_recursive_spin_unlock(&ucs_kh_lock);
}

void ucs_debug_disable_signals()
{
    int signum;

    ucs_recursive_spin_lock(&ucs_kh_lock);
    kh_foreach_key(&ucs_signal_orig_action_map, signum,
                   ucs_debug_disable_signal_nolock(signum));
    ucs_recursive_spin_unlock(&ucs_kh_lock);
}
