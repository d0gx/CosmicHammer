/*
 * CosmicRowhammer - Distributed Cosmic Ray Bit Flip Observer
 * Author: Dr. Antonio Nappa / FuzzSociety
 * Version: 0.4.0
 *
 * Allocates a 512 MB sandboxed memory arena divided into five typed
 * sentinel regions — including a PTE simulation layer — and continuously
 * scans for bit flips induced by cosmic ray Single Event Upsets (SEUs).
 *
 * Each flip is classified by exploitability primitive, accumulated into a
 * configurable-window anonymised report, and optionally POSTed to a remote
 * endpoint.
 *
 * Compile (no curl):  gcc -O2 -Wall -o cosmic_rowhammer cosmic_rowhammer.c -lm
 * Compile (curl):     gcc -O2 -Wall -DWITH_CURL -o cosmic_rowhammer cosmic_rowhammer.c -lm -lcurl
 * Run:                sudo ./cosmic_rowhammer [options]
 *
 * Report window examples:
 *   --report-window 10s    (10 seconds,  for testing)
 *   --report-window 30m    (30 minutes)
 *   --report-window 6h     (6 hours)
 *   --report-window 3d     (3 days,  default = 3d)
 *
 * Docker / container notes (false-positive sources):
 *
 *  1. MADV_HUGEPAGE + khugepaged: the host kernel's THP collapse daemon
 *     asynchronously promotes 4 KB pages to 2 MB pages, briefly unmapping
 *     them during the copy.  This creates transient stale reads in the scan
 *     that look like bit flips.  Fix: MADV_NOHUGEPAGE (default here).
 *
 *  2. KSM (Kernel Samepage Merging): if the host has /sys/kernel/mm/ksm/run=1,
 *     the large uniform sentinel regions are perfect merge candidates.  KSM
 *     marks merged pages CoW-read-only; the restore write in scan_arena triggers
 *     a CoW fault, and the new private page may briefly read back as zero on the
 *     next scan pass.  Fix: MADV_UNMERGEABLE (applied here, needs --privileged
 *     or CAP_SYS_ADMIN on some kernels, but silently ignored if unavailable).
 *
 *  3. Volatile reads: without the volatile qualifier on scan reads, the compiler
 *     can hoist or CSE loads under -O2, making the scan read a stale register
 *     value instead of DRAM.  On ARM Docker hosts the weak memory model amplifies
 *     this.  Fix: cast to volatile uint64_t * inside scan_arena (done here).
 *
 *  Required Docker flags:  --cap-add IPC_LOCK  (for mlock)
 *  Recommended:            --cap-add SYS_ADMIN (for MADV_UNMERGEABLE on older kernels)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <locale.h>
#include <signal.h>
#include <errno.h>
#include <math.h>
#include <fcntl.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <io.h>
#else
#  include <unistd.h>
#  include <sys/mman.h>
#  include <sys/utsname.h>
#  include <sys/sysinfo.h>
#  include <sys/resource.h>
#  include <sys/stat.h>
#  include <cpuid.h>
#endif

#ifdef WITH_CURL
#  include <curl/curl.h>
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

#define ARENA_SIZE        (512UL * 1024 * 1024)   /* 512 MB total             */
#define REGION_COUNT      5                        /* five typed regions       */
/* Round down to nearest 8-byte multiple so every region base and every word
 * index within a region is naturally 8-byte aligned.  Without this,
 * ARENA_SIZE/REGION_COUNT = 0x6666666 (% 8 = 6), leaving a 6-byte uninitialised
 * gap at each boundary that scan_arena reads as a corrupt 64-bit word.       */
#define REGION_SIZE       ((ARENA_SIZE / REGION_COUNT) & ~7UL)  /* 0x6666660  */
#define SCAN_INTERVAL_S   5                        /* seconds between scans    */
#define MAX_FLIPS         8192                     /* ring buffer capacity     */
#define DEFAULT_REPORT_S  (72 * 3600)              /* 72-hour default window   */
#define VERSION           "0.5.0"

/* ═══════════════════════════════════════════════════════════════════════════
 * x86-64 PTE Bit Definitions  (Intel SDM Vol.3A §4.5)
 *
 *  63      NX   — No-Execute  (1 = non-executable)
 *  51:12   PA   — Physical address bits
 *  11:9    AVL  — Available for OS use
 *  8       G    — Global page
 *  7       PAT  — Page Attribute Table index
 *  6       D    — Dirty
 *  5       A    — Accessed
 *  4       PCD  — Page-level Cache Disable
 *  3       PWT  — Page-level Write-Through
 *  2       U/S  — User(1) / Supervisor(0)
 *  1       R/W  — Read-Write(1) / Read-Only(0)
 *  0       P    — Present
 * ═══════════════════════════════════════════════════════════════════════════ */

#define PTE_BIT_P       0   /* Present              */
#define PTE_BIT_RW      1   /* Read/Write           */
#define PTE_BIT_US      2   /* User/Supervisor      */
#define PTE_BIT_PWT     3   /* Write-Through        */
#define PTE_BIT_PCD     4   /* Cache Disable        */
#define PTE_BIT_A       5   /* Accessed             */
#define PTE_BIT_D       6   /* Dirty                */
#define PTE_BIT_NX      63  /* No-Execute           */
#define PTE_PA_SHIFT    12  /* Physical addr starts at bit 12 */

/* FIX: original mask 0x000FFFFFFFFF000 was missing one hex nibble.
 * x86-64 PTE physical address field occupies bits [51:12] = 40 bits.
 * Correct mask: bits 51 down to 12 set = 0x000FFFFFFFFFF000              */
#define PTE_PA_MASK     UINT64_C(0x000FFFFFFFFFF000)

/*
 * Canonical "safe" PTE value used to fill the PTE_SIM region:
 *   Present=1, RW=1, User=1, Accessed=0, Dirty=0, NX=1
 *   Physical address = 0x000000001A000 (arbitrary, page-aligned)
 *
 *   NX(63)=1 | PA=0x1A000 | U/S(2)=1 | R/W(1)=1 | P(0)=1
 *   = 0x8000000001A000_07
 */
#define FILL_PTE_SAFE   UINT64_C(0x8000000001A00007)

/* ═══════════════════════════════════════════════════════════════════════════
 * Sentinel Patterns
 * ═══════════════════════════════════════════════════════════════════════════ */

#define FILL_POINTER    UINT64_C(0x00007FFF12345678)  /* canonical user-space ptr  */
#define FILL_RETADDR    UINT64_C(0x00007FFF87654321)  /* canonical .text ret addr  */
#define FILL_PERMISSION UINT64_C(0x0000000000000004)  /* permission/capability bit */
#define FILL_DATA_A     UINT64_C(0xAAAAAAAAAAAAAAAA)
#define FILL_DATA_B     UINT64_C(0x5555555555555555)

/* ═══════════════════════════════════════════════════════════════════════════
 * Region & Flip Types
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum {
    REGION_POINTER    = 0,
    REGION_RETADDR    = 1,
    REGION_PERMISSION = 2,
    REGION_DATA       = 3,
    REGION_PTE_SIM    = 4,
} RegionType;

static const char *region_names[] = {
    "POINTER", "RETADDR", "PERMISSION", "DATA", "PTE_SIM"
};

typedef enum {
    /* Generic classes */
    FLIP_BENIGN           = 0,
    FLIP_DATA_CORRUPT     = 1,
    FLIP_PTR_HIJACK       = 2,
    FLIP_PRIV_ESC         = 3,
    FLIP_CODE_PAGE        = 4,
    /* PTE-specific classes */
    PTE_PRESENT_CLEAR     = 5,  /* P:  1→0  page fault / DoS            */
    PTE_WRITE_SET         = 6,  /* RW: 0→1  write to read-only mapping  */
    PTE_NX_CLEAR          = 7,  /* NX: 1→0  non-exec becomes executable */
    PTE_PHYS_CORRUPT      = 8,  /* PA: any  arbitrary physical alias     */
    PTE_SUPERVISOR_ESC    = 9,  /* US: 1→0  user page → supervisor only */
    FLIP_CLASS_COUNT      = 10,
} FlipClass;

static const char *flip_class_names[] = {
    "BENIGN", "DATA_CORRUPTION", "PTR_HIJACK", "PRIV_ESC", "CODE_PAGE",
    "PTE_PRESENT_CLEAR", "PTE_WRITE_SET", "PTE_NX_CLEAR",
    "PTE_PHYS_CORRUPT",  "PTE_SUPERVISOR_ESC"
};

/* Human-readable exploit primitive description */
static const char *flip_class_desc[] = {
    "No control-flow impact",
    "Memory corruption, no CFI bypass",
    "Potential control-flow hijack via pointer corruption",
    "Potential privilege escalation via flag corruption",
    "Return address corruption → code execution",
    "PTE Present bit cleared → page fault / DoS",
    "PTE Write bit set → write to read-only mapping",
    "PTE NX bit cleared → heap/stack becomes executable",
    "PTE physical address bits corrupted → arbitrary memory alias",
    "PTE User bit cleared → user page becomes supervisor-only"
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Flip Event
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint64_t   timestamp;      /* unix epoch                           */
    size_t     offset;         /* byte offset within arena             */
    uint8_t    bit_position;   /* 0-63 within the 64-bit word          */
    uint64_t   expected;       /* sentinel value                       */
    uint64_t   observed;       /* actual value read back               */
    int        direction;      /* +1 = 0→1 ,  -1 = 1→0               */
    int        n_bits;         /* number of bits that flipped          */
    RegionType region;
    FlipClass  flip_class;
    uint32_t   dram_row;       /* estimated DRAM row  (offset / 8192)  */
} FlipEvent;

/* ═══════════════════════════════════════════════════════════════════════════
 * Report Accumulator
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    time_t     window_start;
    time_t     window_end;
    uint64_t   scan_cycles;
    uint64_t   total_bits;
    uint64_t   zero_to_one;
    uint64_t   one_to_zero;
    uint64_t   multi_bit_events;
    uint64_t   dram_rows_seen;   /* unique rows — approximated          */
    uint64_t   by_class[FLIP_CLASS_COUNT];
    uint64_t   by_region[REGION_COUNT];
} ReportWindow;

/* ═══════════════════════════════════════════════════════════════════════════
 * Global State
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint8_t     *arena              = NULL;
static FlipEvent    flip_ring[MAX_FLIPS];
static size_t       flip_head          = 0;
static size_t       flip_total         = 0;
static volatile int running            = 1;
static char         report_url[512]    = {0};
static int          opt_altitude       = -1;   /* metres, -1 = not set  */
static int          opt_interval       = SCAN_INTERVAL_S;
static long         opt_report_window  = DEFAULT_REPORT_S; /* configurable */
static ReportWindow report_win         = {0};

typedef struct {
    char          sysname[32];
    char          release[64];
    char          machine[32];
    unsigned long ram_mb;
} HostInfo;

/* ═══════════════════════════════════════════════════════════════════════════
 * Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static void sig_handler(int sig) { (void)sig; running = 0; }

static const char *ts_now(char *buf, size_t n) {
    time_t t = time(NULL);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    return buf;
}

static int count_flipped_bits(uint64_t a, uint64_t b) {
    return __builtin_popcountll(a ^ b);
}

static void platform_init_console(void) {
#ifdef _WIN32
    HANDLE h;
    DWORD mode;

    /* Force UTF-8 console code pages so Unicode banners/logs render without
     * requiring users to manually run chcp/encoding commands every session. */
    h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode))
        SetConsoleOutputCP(CP_UTF8);

    h = GetStdHandle(STD_INPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode))
        SetConsoleCP(CP_UTF8);

    setlocale(LC_ALL, ".UTF-8");
#else
    setlocale(LC_ALL, "");
#endif
}

static void platform_sleep_seconds(unsigned seconds) {
#ifdef _WIN32
    Sleep(seconds * 1000U);
#else
    sleep(seconds);
#endif
}

static void platform_get_host_info(HostInfo *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));

#ifdef _WIN32
    SYSTEM_INFO si;
    MEMORYSTATUSEX ms;
    const char *arch = "unknown";

    GetNativeSystemInfo(&si);
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms))
        ms.ullTotalPhys = 0;

    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: arch = "x86_64"; break;
        case PROCESSOR_ARCHITECTURE_INTEL: arch = "x86"; break;
#ifdef PROCESSOR_ARCHITECTURE_ARM64
        case PROCESSOR_ARCHITECTURE_ARM64: arch = "arm64"; break;
#endif
#ifdef PROCESSOR_ARCHITECTURE_ARM
        case PROCESSOR_ARCHITECTURE_ARM: arch = "arm"; break;
#endif
        default: break;
    }

    snprintf(out->sysname, sizeof(out->sysname), "Windows");
    snprintf(out->release, sizeof(out->release), "NT");
    snprintf(out->machine, sizeof(out->machine), "%s", arch);
    out->ram_mb = (unsigned long)(ms.ullTotalPhys / (1024ULL * 1024ULL));
#else
    struct utsname u;
    struct sysinfo si;

    if (uname(&u) == 0) {
        snprintf(out->sysname, sizeof(out->sysname), "%s", u.sysname);
        snprintf(out->release, sizeof(out->release), "%s", u.release);
        snprintf(out->machine, sizeof(out->machine), "%s", u.machine);
    } else {
        snprintf(out->sysname, sizeof(out->sysname), "Linux");
        snprintf(out->release, sizeof(out->release), "unknown");
        snprintf(out->machine, sizeof(out->machine), "unknown");
    }

    if (sysinfo(&si) == 0)
        out->ram_mb = si.totalram / (1024UL * 1024UL);
    else
        out->ram_mb = 0;
#endif
}

static int platform_detect_ecc(void) {
#ifdef _WIN32
    return 0;
#else
    FILE *f = fopen("/sys/devices/system/edac/mc/mc0/ce_count", "r");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
#endif
}

static void platform_release_arena(uint8_t *p) {
    if (!p) return;
#ifdef _WIN32
    VirtualUnlock(p, ARENA_SIZE);
    if (!VirtualFree(p, 0, MEM_RELEASE))
        fprintf(stderr, "[!] VirtualFree failed (error=%lu)\n", (unsigned long)GetLastError());
#else
    munlock(p, ARENA_SIZE);
    munmap(p, ARENA_SIZE);
#endif
}

#ifdef _WIN32
static unsigned long long bytes_to_mb_u64(size_t bytes) {
    return (unsigned long long)(bytes / (1024ULL * 1024ULL));
}

static void win32_error_text(DWORD err, char *buf, size_t bufsz) {
    if (!buf || bufsz == 0) return;
    buf[0] = '\0';

    DWORD n = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, 0, buf, (DWORD)bufsz, NULL
    );

    if (!n) {
        snprintf(buf, bufsz, "Unknown Win32 error");
        return;
    }

    while (n > 0 && (buf[n - 1] == '\r' || buf[n - 1] == '\n' || buf[n - 1] == '.'))
        buf[--n] = '\0';
}

static int platform_raise_working_set(size_t lock_bytes) {
    HANDLE h = GetCurrentProcess();
    SIZE_T min_ws = 0, max_ws = 0;
    DWORD flags = 0;
    char errtxt[256];

    if (!GetProcessWorkingSetSizeEx(h, &min_ws, &max_ws, &flags)) {
        DWORD err = GetLastError();
        win32_error_text(err, errtxt, sizeof(errtxt));
        fprintf(stderr,
            "[~] Could not read working set limits (error=%lu: %s).\n"
            "    VirtualLock may fail if the default quota is too small.\n",
            (unsigned long)err, errtxt);
        return 0;
    }

    {
        const size_t headroom = 256ULL * 1024ULL * 1024ULL;
        SIZE_T desired_min = (SIZE_T)lock_bytes + (SIZE_T)headroom;
        SIZE_T desired_max = desired_min + (SIZE_T)headroom;

        if (desired_max < desired_min) desired_max = desired_min;

        if (min_ws >= desired_min && max_ws >= desired_max) {
            return 1; /* Already large enough. */
        }

        if (!SetProcessWorkingSetSizeEx(h, desired_min, desired_max, flags)) {
            DWORD err = GetLastError();
            BOOL in_job = FALSE;
            win32_error_text(err, errtxt, sizeof(errtxt));
            (void)IsProcessInJob(h, NULL, &in_job);

            fprintf(stderr,
                "[~] Auto-tune working set failed (error=%lu: %s)\n"
                "    Current limits: min=%llu MB max=%llu MB\n"
                "    Requested:      min=%llu MB max=%llu MB\n",
                (unsigned long)err, errtxt,
                bytes_to_mb_u64((size_t)min_ws), bytes_to_mb_u64((size_t)max_ws),
                bytes_to_mb_u64((size_t)desired_min), bytes_to_mb_u64((size_t)desired_max));

            if (err == ERROR_PRIVILEGE_NOT_HELD || err == ERROR_ACCESS_DENIED)
                fprintf(stderr,
                    "    Hint: run in an elevated (Administrator) terminal; "
                    "Windows may require higher privileges to raise working set limits.\n");

            if (in_job)
                fprintf(stderr,
                    "    Hint: this process is inside a Job object (common in IDE shells), "
                    "which can enforce memory quotas.\n");

            return 0;
        }

        if (GetProcessWorkingSetSizeEx(h, &min_ws, &max_ws, &flags)) {
            printf("[+] Working set tuned for locking: min=%llu MB max=%llu MB\n",
                   bytes_to_mb_u64((size_t)min_ws), bytes_to_mb_u64((size_t)max_ws));
        } else {
            printf("[+] Working set tuning requested before VirtualLock.\n");
        }
    }

    return 1;
}

static void platform_diag_virtuallock_failure(DWORD err, size_t lock_bytes) {
    HANDLE h = GetCurrentProcess();
    SIZE_T min_ws = 0, max_ws = 0;
    DWORD flags = 0;
    BOOL in_job = FALSE;
    char errtxt[256];

    win32_error_text(err, errtxt, sizeof(errtxt));
    (void)GetProcessWorkingSetSizeEx(h, &min_ws, &max_ws, &flags);
    (void)IsProcessInJob(h, NULL, &in_job);

    fprintf(stderr,
        "[~] VirtualLock failed (error=%lu: %s)\n"
        "    Lock request: %llu MB\n"
        "    Working set:  min=%llu MB max=%llu MB\n",
        (unsigned long)err, errtxt,
        bytes_to_mb_u64(lock_bytes),
        bytes_to_mb_u64((size_t)min_ws), bytes_to_mb_u64((size_t)max_ws));

    if (err == ERROR_WORKING_SET_QUOTA)
        fprintf(stderr,
            "    Cause: working set quota is too small for this lock request.\n");

    if (err == ERROR_PRIVILEGE_NOT_HELD || err == ERROR_ACCESS_DENIED)
        fprintf(stderr,
            "    Cause: insufficient privilege to lock this amount of memory.\n");

    if (in_job)
        fprintf(stderr,
            "    Note: process is inside a Job object; quota policies may be enforced externally.\n");

    fprintf(stderr,
        "    Recommendation: run from an elevated terminal and/or lower arena size.\n"
        "    The scanner will continue, but page residency is less stable and accuracy may drop.\n");
}
#endif

/* ─── Report window parser ─────────────────────────────────────────────────
 * Accepts:  10s  30m  6h  3d  (or bare integer = seconds)
 * Returns:  seconds, or -1 on parse error
 * ─────────────────────────────────────────────────────────────────────────*/
static long parse_report_window(const char *s) {
    if (!s || !*s) return -1;
    char *end = NULL;
    long val = strtol(s, &end, 10);
    if (end == s || val <= 0) return -1;   /* no digits or non-positive */

    if (*end == '\0' || *end == 's' || *end == 'S') return val;
    if (*end == 'm'  || *end == 'M') return val * 60L;
    if (*end == 'h'  || *end == 'H') return val * 3600L;
    if (*end == 'd'  || *end == 'D') return val * 86400L;

    return -1;  /* unknown suffix */
}

/* Pretty-print seconds as "Xd Yh Zm Ws" (omitting zero fields) */
static const char *fmt_duration(long secs, char *buf, size_t n) {
    long d = secs / 86400, h = (secs % 86400) / 3600;
    long m = (secs % 3600) / 60,  s = secs % 60;
    char tmp[64] = {0};
    if (d) snprintf(tmp + strlen(tmp), sizeof(tmp) - strlen(tmp), "%ldd ", d);
    if (h) snprintf(tmp + strlen(tmp), sizeof(tmp) - strlen(tmp), "%ldh ", h);
    if (m) snprintf(tmp + strlen(tmp), sizeof(tmp) - strlen(tmp), "%ldm ", m);
    if (s || !tmp[0]) snprintf(tmp + strlen(tmp), sizeof(tmp) - strlen(tmp), "%lds", s);
    /* trim trailing space */
    size_t l = strlen(tmp);
    if (l > 0 && tmp[l-1] == ' ') tmp[l-1] = '\0';
    snprintf(buf, n, "%s", tmp);
    return buf;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Container / Environment Detection
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Returns 1 if we appear to be running inside a container (Docker / LXC / etc.) */
static int detect_container(void) {
#ifdef _WIN32
    return 0;
#else
    /* Most reliable: Docker always creates /.dockerenv                  */
    if (access("/.dockerenv", F_OK) == 0) return 1;
    /* cgroup v1: docker sets a non-trivial cgroup path                  */
    FILE *f = fopen("/proc/1/cgroup", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "docker") || strstr(line, "lxc") ||
                strstr(line, "containerd") || strstr(line, "kubepods")) {
                fclose(f); return 1;
            }
        }
        fclose(f);
    }
    return 0;
#endif
}

/* Check cgroup v1 memory limit; returns bytes or 0 if unlimited / unavailable */
static uint64_t cgroup_mem_limit(void) {
#ifdef _WIN32
    return 0;
#else
    const char *paths[] = {
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        "/sys/fs/cgroup/memory.max",          /* cgroup v2 */
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        FILE *f = fopen(paths[i], "r");
        if (!f) continue;
        uint64_t val = 0;
        if (fscanf(f, "%llu", (unsigned long long *)&val) == 1) {
            fclose(f);
            /* Kernel uses 9223372036854771712 (near UINT64_MAX) for "unlimited" */
            if (val > (uint64_t)8 * 1024 * 1024 * 1024 * 1024ULL) return 0;
            return val;
        }
        fclose(f);
    }
    return 0;
#endif
}

/* Check if host KSM is active */
static int ksm_active(void) {
#ifdef _WIN32
    return 0;
#else
    FILE *f = fopen("/sys/kernel/mm/ksm/run", "r");
    if (!f) return 0;
    int v = 0;
    if (fscanf(f, "%d", &v) != 1) v = 0;
    fclose(f);
    return v;
#endif
}

/* Check host THP policy */
static const char *thp_policy(void) {
#ifdef _WIN32
    return "n/a";
#else
    FILE *f = fopen("/sys/kernel/mm/transparent_hugepage/enabled", "r");
    if (!f) return "unknown";
    static char buf[64]; buf[0] = '\0';
    if (!fgets(buf, sizeof(buf), f)) buf[0] = '\0';
    fclose(f);
    /* File contains e.g. "always [madvise] never" — extract the bracketed one */
    char *s = strchr(buf, '[');
    char *e = s ? strchr(s, ']') : NULL;
    if (s && e) { *e = '\0'; return s + 1; }
    return buf;
#endif
}



/* ═══════════════════════════════════════════════════════════════════════════
 * Arena Allocation
 *
 * Key decisions for container environments:
 *
 *  MADV_NOHUGEPAGE  — prevents khugepaged from asynchronously promoting our
 *                     4 KB sentinel pages to 2 MB THP during a scan pass,
 *                     which would cause transient stale reads (false flips).
 *
 *  MADV_UNMERGEABLE — tells KSM not to merge our pages with any others.
 *                     Without this, the large uniform sentinel regions are
 *                     prime KSM targets; a merged CoW restore write triggers
 *                     a kernel page-copy that looks like a flip on the next
 *                     scan.  Requires CAP_SYS_ADMIN on some kernel versions;
 *                     failure is non-fatal (we warn and continue).
 *
 *  MADV_DONTDUMP    — omit the 512 MB arena from core dumps; speeds up crash
 *                     handling and prevents accidental sentinel-data leaks.
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint8_t *alloc_arena(void) {
#ifdef _WIN32
    void *p = VirtualAlloc(NULL, ARENA_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p) {
        DWORD err = GetLastError();
        char errtxt[256];
        win32_error_text(err, errtxt, sizeof(errtxt));
        fprintf(stderr, "[!] VirtualAlloc failed (error=%lu: %s)\n", (unsigned long)err, errtxt);
        return NULL;
    }

    (void)platform_raise_working_set(ARENA_SIZE);

    if (!VirtualLock(p, ARENA_SIZE))
        platform_diag_virtuallock_failure(GetLastError(), ARENA_SIZE);
    else
        printf("[+] Arena locked with VirtualLock.\n");

    return (uint8_t *)p;
#else
    /* Check cgroup limit before attempting mlock */
    uint64_t cg_limit = cgroup_mem_limit();
    if (cg_limit > 0 && cg_limit < ARENA_SIZE) {
        fprintf(stderr,
            "[!] WARNING: cgroup memory limit is %llu MB — arena is 512 MB.\n"
            "    mlock will likely fail or pages will be reclaimed under pressure.\n"
            "    Run with: docker run --memory 768m  (or larger)\n\n",
            (unsigned long long)(cg_limit / (1024*1024)));
    }

    void *p = mmap(NULL, ARENA_SIZE,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                   -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); return NULL; }

    /* ── Disable THP: prevents khugepaged false-positive flips ── */
#ifdef MADV_NOHUGEPAGE
    if (madvise(p, ARENA_SIZE, MADV_NOHUGEPAGE) != 0)
        fprintf(stderr, "[~] MADV_NOHUGEPAGE unavailable (%s) — THP may cause false positives\n",
                strerror(errno));
#endif

    /* ── Disable KSM merging: prevents CoW-restore false-positive flips ── */
#ifdef MADV_UNMERGEABLE
    if (madvise(p, ARENA_SIZE, MADV_UNMERGEABLE) != 0)
        fprintf(stderr, "[~] MADV_UNMERGEABLE failed (%s) — add --cap-add SYS_ADMIN if KSM is active\n",
                strerror(errno));
#endif

    /* ── Omit from core dumps ── */
#ifdef MADV_DONTDUMP
    madvise(p, ARENA_SIZE, MADV_DONTDUMP);
#endif

    /* ── Lock pages: requires CAP_IPC_LOCK or root ── */
    if (mlock(p, ARENA_SIZE) != 0)
        fprintf(stderr,
            "[!] mlock failed (%s)\n"
            "    Without locked pages, the kernel may swap/reclaim arena pages\n"
            "    between spray and scan, causing false positives.\n"
            "    Ensure: docker run --cap-add IPC_LOCK, run as root, cgroup limit >= 768 MB\n",
            strerror(errno));
    else
        printf("[+] Arena mlocked — pages pinned in RAM.\n");

    return (uint8_t *)p;
#endif
}


/* ═══════════════════════════════════════════════════════════════════════════
 * PTE Simulation Fill
 *
 * Each 64-bit word in the PTE_SIM region is a structurally valid x86-64
 * 4KB page PTE with a unique-per-word physical address derived from its
 * index, so we can distinguish corruption of the PA field from bit flips
 * in the control bits.
 *
 *   word[i] = NX(63)=1 | phys_pfn(i) << 12 | U/S(2)=1 | R/W(1)=1 | P(0)=1
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Fixed control bits for the canonical safe PTE (NX=1, U=1, RW=1, P=1) */
#define PTE_CTRL_BITS   UINT64_C(0x8000000000000007)

static inline uint64_t pte_for_index(size_t i) {
    /* Physical PFN cycles through a 20-bit space — avoids bit collisions
     * with control bits. Shift left 12 to place in PA field.            */
    uint64_t pfn = (uint64_t)(i & 0xFFFFF);       /* 20-bit PFN           */
    return PTE_CTRL_BITS | (pfn << PTE_PA_SHIFT);
}

static void fill_arena(uint8_t *base) {
    size_t words = REGION_SIZE / sizeof(uint64_t);
    uint64_t *r;

    r = (uint64_t *)(base + REGION_POINTER    * REGION_SIZE);
    for (size_t i = 0; i < words; i++) r[i] = FILL_POINTER;

    r = (uint64_t *)(base + REGION_RETADDR    * REGION_SIZE);
    for (size_t i = 0; i < words; i++) r[i] = FILL_RETADDR;

    r = (uint64_t *)(base + REGION_PERMISSION * REGION_SIZE);
    for (size_t i = 0; i < words; i++) r[i] = FILL_PERMISSION;

    r = (uint64_t *)(base + REGION_DATA       * REGION_SIZE);
    for (size_t i = 0; i < words; i++) r[i] = (i & 1) ? FILL_DATA_B : FILL_DATA_A;

    /* PTE_SIM: unique per-word PTE so physical-address flips are detectable */
    r = (uint64_t *)(base + REGION_PTE_SIM    * REGION_SIZE);
    for (size_t i = 0; i < words; i++) r[i] = pte_for_index(i);

    __sync_synchronize();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Expected Value Lookup
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint64_t expected_at(size_t byte_off) {
    RegionType r = (RegionType)(byte_off / REGION_SIZE);
    size_t word_idx = (byte_off - r * REGION_SIZE) / sizeof(uint64_t);
    switch (r) {
        case REGION_POINTER:    return FILL_POINTER;
        case REGION_RETADDR:    return FILL_RETADDR;
        case REGION_PERMISSION: return FILL_PERMISSION;
        case REGION_DATA:       return (word_idx & 1) ? FILL_DATA_B : FILL_DATA_A;
        case REGION_PTE_SIM:    return pte_for_index(word_idx);
        default:                return 0;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PTE Flip Classifier
 *
 * Receives the expected (canonical) PTE and the observed (flipped) PTE.
 * Returns the most severe applicable PTE_* class.
 * ═══════════════════════════════════════════════════════════════════════════ */

static FlipClass classify_pte_flip(uint64_t expected, uint64_t observed) {
    uint64_t diff = expected ^ observed;

    /* NX bit cleared: 1→0 → non-exec page becomes executable
     * Checked first — highest exploitability severity               */
    if ((diff >> PTE_BIT_NX) & 1) {
        if (!((observed >> PTE_BIT_NX) & 1))   /* was 1, now 0 */
            return PTE_NX_CLEAR;
    }

    /* Physical address bits corrupted → arbitrary memory aliasing */
    if (diff & PTE_PA_MASK)
        return PTE_PHYS_CORRUPT;

    /* Present bit cleared: 1→0 → page-fault loop / DoS */
    if ((diff >> PTE_BIT_P) & 1) {
        if (!((observed >> PTE_BIT_P) & 1))
            return PTE_PRESENT_CLEAR;
    }

    /* Write bit set: 0→1 → RO mapping becomes writable */
    if ((diff >> PTE_BIT_RW) & 1) {
        if ((observed >> PTE_BIT_RW) & 1)
            return PTE_WRITE_SET;
    }

    /* User/Supervisor bit cleared: 1→0 → user page locked out */
    if ((diff >> PTE_BIT_US) & 1) {
        if (!((observed >> PTE_BIT_US) & 1))
            return PTE_SUPERVISOR_ESC;
    }

    /* Anything else in a PTE is still a corruption */
    return FLIP_DATA_CORRUPT;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Generic Flip Classifier
 * ═══════════════════════════════════════════════════════════════════════════ */

static FlipClass classify_flip(RegionType region, uint64_t expected,
                                uint64_t observed, int direction, int n_bits) {
    /* Multi-bit single-word flips are statistically improbable for cosmic
     * rays — flag as benign / noise to avoid false positives.
     * Threshold >2 kept intentionally: genuine double-bit events exist
     * near the Bragg peak, but >2 is almost certainly electrical noise.  */
    if (n_bits > 2) return FLIP_BENIGN;

    switch (region) {
        case REGION_PTE_SIM:
            return classify_pte_flip(expected, observed);
        case REGION_POINTER:
            return (direction > 0) ? FLIP_PTR_HIJACK : FLIP_DATA_CORRUPT;
        case REGION_RETADDR:
            return FLIP_CODE_PAGE;
        case REGION_PERMISSION:
            return (direction > 0) ? FLIP_PRIV_ESC : FLIP_BENIGN;
        case REGION_DATA:
        default:
            return FLIP_DATA_CORRUPT;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Read Spray  (observation — no writes)
 *
 * Touches every page (stride = one cache line per page) to keep all arena
 * pages resident and warm in the TLB before each scan pass.
 * ═══════════════════════════════════════════════════════════════════════════ */

static void spray_pass(uint8_t *base) {
    volatile uint64_t *p = (volatile uint64_t *)base;
    /* Stride = 4096 bytes / 8 bytes-per-word = 512 words.
     * This touches exactly one word per 4 KB page — enough to fault
     * pages back in if they were reclaimed, without thrashing L1.      */
    size_t stride = 4096 / sizeof(uint64_t);
    size_t total  = ARENA_SIZE / sizeof(uint64_t);
    for (size_t i = 0; i < total; i += stride) (void)p[i];
    __sync_synchronize();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Arena Scan
 * ═══════════════════════════════════════════════════════════════════════════ */

static size_t scan_arena(uint8_t *base) {
    /* Cast to volatile: forces the compiler to issue a real load for every
     * word.  Without this, -O2 may hoist or CSE reads from the non-volatile
     * pointer, causing the scan to compare a stale register value against
     * the expected sentinel — producing phantom flips, especially on ARM.  */
    volatile uint64_t *words = (volatile uint64_t *)base;
    size_t total    = ARENA_SIZE / sizeof(uint64_t);
    size_t found    = 0;
    char   ts[32];
    ts_now(ts, sizeof(ts));

    for (size_t i = 0; i < total; i++) {
        size_t   byte_off = i * sizeof(uint64_t);
        uint64_t expected = expected_at(byte_off);
        uint64_t observed = words[i];

        if (__builtin_expect(observed == expected, 1)) continue;

        /* ── Flip detected ──────────────────────────────────────────── */
        uint64_t   diff    = expected ^ observed;
        uint8_t    bit_pos = (uint8_t)__builtin_ctzll(diff);
        int        dir     = ((observed >> bit_pos) & 1) ? +1 : -1;
        int        n_bits  = count_flipped_bits(expected, observed);
        RegionType rtype   = (RegionType)(byte_off / REGION_SIZE);
        FlipClass  fclass  = classify_flip(rtype, expected, observed, dir, n_bits);
        uint32_t   drow    = (uint32_t)(byte_off / 8192);

        FlipEvent ev = {
            .timestamp    = (uint64_t)time(NULL),
            .offset       = byte_off,
            .bit_position = bit_pos,
            .expected     = expected,
            .observed     = observed,
            .direction    = dir,
            .n_bits       = n_bits,
            .region       = rtype,
            .flip_class   = fclass,
            .dram_row     = drow,
        };

        flip_ring[flip_head % MAX_FLIPS] = ev;
        flip_head++;
        flip_total++;
        found++;

        /* ── Update report accumulator ──────────────────────────────── */
        report_win.total_bits += (uint64_t)n_bits;
        if (dir > 0) report_win.zero_to_one++; else report_win.one_to_zero++;
        if (n_bits > 1) report_win.multi_bit_events++;
        report_win.by_class[fclass]++;
        report_win.by_region[rtype]++;
        report_win.dram_rows_seen++;    /* crude; dedup can be added later */

        /* ── Console output ─────────────────────────────────────────── */
        printf("[%s] ══ FLIP DETECTED ══\n"
               "  offset     = 0x%010zx  (DRAM row ~%u)\n"
               "  bit        = %2u  direction = %s  n_bits = %d\n"
               "  expected   = 0x%016llx\n"
               "  observed   = 0x%016llx\n"
               "  region     = %s\n"
               "  class      = %s\n"
               "  primitive  = %s\n\n",
               ts,
               byte_off, drow,
               bit_pos, (dir > 0) ? "0→1" : "1→0", n_bits,
               (unsigned long long)expected,
               (unsigned long long)observed,
               region_names[rtype],
               flip_class_names[fclass],
               flip_class_desc[fclass]);

        /* If this is a PTE flip, add PTE-specific detail */
        if (rtype == REGION_PTE_SIM) {
            printf("  [PTE] P=%llu RW=%llu U/S=%llu NX=%llu  PA=0x%09llx\n"
                   "        flipped_bits: P=%llu RW=%llu U/S=%llu NX=%llu PA_bits=%llu\n\n",
                   (unsigned long long)((observed >> PTE_BIT_P)  & 1),
                   (unsigned long long)((observed >> PTE_BIT_RW) & 1),
                   (unsigned long long)((observed >> PTE_BIT_US) & 1),
                   (unsigned long long)((observed >> PTE_BIT_NX) & 1),
                   (unsigned long long)((observed & PTE_PA_MASK) >> PTE_PA_SHIFT),
                   (unsigned long long)((diff >> PTE_BIT_P)  & 1),
                   (unsigned long long)((diff >> PTE_BIT_RW) & 1),
                   (unsigned long long)((diff >> PTE_BIT_US) & 1),
                   (unsigned long long)((diff >> PTE_BIT_NX) & 1),
                   (unsigned long long)(!!(diff & PTE_PA_MASK)));
        }

        fflush(stdout);

        /* Restore sentinel so the word isn't re-reported next scan.
         * The volatile write ensures the store actually reaches the cache
         * line and is not eliminated by the compiler.                   */
        words[i] = expected;
    }

    return found;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * JSON Report Builder
 * ═══════════════════════════════════════════════════════════════════════════ */

static void build_report_json(char *buf, size_t bufsz, const ReportWindow *w) {
    HostInfo hi;
    platform_get_host_info(&hi);
    char wstart[32], wend[32];

    strftime(wstart, sizeof(wstart), "%Y-%m-%dT%H:%M:%SZ", gmtime(&w->window_start));
    strftime(wend,   sizeof(wend),   "%Y-%m-%dT%H:%M:%SZ", gmtime(&w->window_end));

    /* Detect ECC heuristically (sysfs) — best-effort */
    int ecc = platform_detect_ecc();

    /* Build altitude string separately to avoid compound-literal in snprintf */
    char alt_str[16];
    if (opt_altitude >= 0)
        snprintf(alt_str, sizeof(alt_str), "%d", opt_altitude);
    else
        snprintf(alt_str, sizeof(alt_str), "null");

    /* Report window in hours (float) for the JSON field */
    double window_hours = (double)opt_report_window / 3600.0;

    snprintf(buf, bufsz,
        "{\n"
        "  \"schema_version\": \"1.1\",\n"
        "  \"window_hours\": %.4g,\n"
        "  \"window_start\": \"%s\",\n"
        "  \"window_end\":   \"%s\",\n"
        "  \"platform\": {\n"
        "    \"arch\":       \"%s\",\n"
        "    \"os\":         \"%s %s\",\n"
        "    \"ram_mb\":     %lu,\n"
        "    \"ecc\":        %s,\n"
        "    \"altitude_m\": %s\n"
        "  },\n"
        "  \"flip_totals\": {\n"
        "    \"total_bits_observed\": %llu,\n"
        "    \"zero_to_one\":         %llu,\n"
        "    \"one_to_zero\":         %llu\n"
        "  },\n"
        "  \"by_class\": {\n"
        "    \"BENIGN\":              %llu,\n"
        "    \"DATA_CORRUPTION\":     %llu,\n"
        "    \"PTR_HIJACK\":          %llu,\n"
        "    \"PRIV_ESC\":            %llu,\n"
        "    \"CODE_PAGE\":           %llu,\n"
        "    \"PTE_PRESENT_CLEAR\":   %llu,\n"
        "    \"PTE_WRITE_SET\":       %llu,\n"
        "    \"PTE_NX_CLEAR\":        %llu,\n"
        "    \"PTE_PHYS_CORRUPT\":    %llu,\n"
        "    \"PTE_SUPERVISOR_ESC\":  %llu\n"
        "  },\n"
        "  \"by_region\": {\n"
        "    \"POINTER\":    %llu,\n"
        "    \"RETADDR\":    %llu,\n"
        "    \"PERMISSION\": %llu,\n"
        "    \"DATA\":       %llu,\n"
        "    \"PTE_SIM\":    %llu\n"
        "  },\n"
        "  \"dram_rows_affected\": %llu,\n"
        "  \"multi_bit_events\":   %llu,\n"
        "  \"scan_cycles\":        %llu\n"
        "}\n",
        window_hours, wstart, wend,
        hi.machine,
        hi.sysname, hi.release,
        hi.ram_mb,
        ecc ? "true" : "false",
        alt_str,
        /* flip_totals */
        (unsigned long long)w->total_bits,
        (unsigned long long)w->zero_to_one,
        (unsigned long long)w->one_to_zero,
        /* by_class */
        (unsigned long long)w->by_class[FLIP_BENIGN],
        (unsigned long long)w->by_class[FLIP_DATA_CORRUPT],
        (unsigned long long)w->by_class[FLIP_PTR_HIJACK],
        (unsigned long long)w->by_class[FLIP_PRIV_ESC],
        (unsigned long long)w->by_class[FLIP_CODE_PAGE],
        (unsigned long long)w->by_class[PTE_PRESENT_CLEAR],
        (unsigned long long)w->by_class[PTE_WRITE_SET],
        (unsigned long long)w->by_class[PTE_NX_CLEAR],
        (unsigned long long)w->by_class[PTE_PHYS_CORRUPT],
        (unsigned long long)w->by_class[PTE_SUPERVISOR_ESC],
        /* by_region */
        (unsigned long long)w->by_region[REGION_POINTER],
        (unsigned long long)w->by_region[REGION_RETADDR],
        (unsigned long long)w->by_region[REGION_PERMISSION],
        (unsigned long long)w->by_region[REGION_DATA],
        (unsigned long long)w->by_region[REGION_PTE_SIM],
        /* misc */
        (unsigned long long)w->dram_rows_seen,
        (unsigned long long)w->multi_bit_events,
        (unsigned long long)w->scan_cycles
    );
}

/* ─── Dump JSON to file ──────────────────────────────────────────────────── */

static void dump_report_to_file(const char *json) {
    char fname[64];
    snprintf(fname, sizeof(fname), "cr_report_%llu.json", (unsigned long long)time(NULL));
    FILE *f = fopen(fname, "w");
    if (!f) { perror("fopen report"); return; }
    fputs(json, f);
    fclose(f);
    printf("[*] Report saved → %s\n", fname);
}

/* ─── POST JSON via libcurl (optional) ──────────────────────────────────── */

#ifdef WITH_CURL
static void post_report(const char *json, const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) return;

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, "User-Agent: CosmicRowhammer/" VERSION);

    curl_easy_setopt(curl, CURLOPT_URL,            url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     json);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     hdrs);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK)
        fprintf(stderr, "[!] Report POST failed: %s\n", curl_easy_strerror(res));
    else
        printf("[+] Report POSTed to %s\n", url);

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
}
#else
static void post_report(const char *json, const char *url) {
    (void)json; (void)url;
    printf("[!] Built without curl — remote reporting disabled.\n"
           "    Recompile with: gcc -DWITH_CURL ... -lcurl\n");
}
#endif

/* ─── Emit report at end of window ─────────────────────────────────────── */

static void emit_report(void) {
    static char json[8192];
    report_win.window_end = time(NULL);
    build_report_json(json, sizeof(json), &report_win);

    char dur[32];
    fmt_duration(opt_report_window, dur, sizeof(dur));

    printf("\n╔══════════════════════════════════════╗\n"
           "║   WINDOW REPORT  (%s, anonymised)%*s║\n"
           "╚══════════════════════════════════════╝\n%s\n",
           dur, (int)(14 - (int)strlen(dur)), " ", json);

    dump_report_to_file(json);

    if (report_url[0])
        post_report(json, report_url);

    /* Reset window */
    memset(&report_win, 0, sizeof(report_win));
    report_win.window_start = time(NULL);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * System Info Banner
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_banner(void) {
    HostInfo hi;
    platform_get_host_info(&hi);
    char dur[32];
    fmt_duration(opt_report_window, dur, sizeof(dur));

    int   in_container = detect_container();
    int   ksm          = ksm_active();
    const char *thp    = thp_policy();
    uint64_t cg        = cgroup_mem_limit();
    const char *thp_hint =
#ifdef _WIN32
        "";
#else
        " (set to 'never' or 'madvise' for best results)";
#endif

    char cg_str[48] = "";
    if (cg) snprintf(cg_str, sizeof(cg_str), "  (cgroup limit: %llu MB)",
                     (unsigned long long)(cg / (1024*1024)));

    printf("╔═══════════════════════════════════════════════════╗\n"
           "║   ☄  CosmicRowhammer v%-6s  —  FuzzSociety      ║\n"
           "╚═══════════════════════════════════════════════════╝\n"
           "  Host      %s %s %s\n"
           "  RAM       %lu MB%s\n"
           "  Container %s\n"
           "  KSM       %s\n"
           "  THP       %s%s\n"
           "  Arena     512 MB  /  5 regions  (~102 MB each)\n"
           "  Regions   POINTER | RETADDR | PERMISSION | DATA | PTE_SIM\n"
           "  Interval  %d s\n"
           "  Window    %s%s\n"
           "  Curl      %s\n",
           VERSION,
           hi.sysname, hi.release, hi.machine,
           hi.ram_mb, cg_str,
           in_container ? "YES — THP/KSM mitigations applied" : "no",
           ksm  ? "ACTIVE ⚠  (host KSM may merge arena pages — false positives possible)" : "off",
           thp, thp_hint,
           opt_interval,
           dur,
           report_url[0] ? " → remote POST" : " → local JSON",
#ifdef WITH_CURL
           "enabled"
#else
           "disabled (recompile with -DWITH_CURL)"
#endif
    );
    if (opt_altitude >= 0)
        printf("  Altitude  %d m\n", opt_altitude);
    if (in_container && ksm)
        printf("\n  [!] KSM is active on the host. Add --cap-add SYS_ADMIN to suppress\n"
               "      via MADV_UNMERGEABLE, or disable on host: echo 0 > /sys/kernel/mm/ksm/run\n");
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Session Stats
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_stats(time_t start) {
    time_t elapsed = time(NULL) - start;
    size_t counts[FLIP_CLASS_COUNT] = {0};
    size_t n = (flip_total < MAX_FLIPS) ? flip_total : MAX_FLIPS;
    for (size_t i = 0; i < n; i++) counts[flip_ring[i].flip_class]++;

    printf("\n─── Session Stats ───────────────────────────────────\n"
           "  Runtime        %ld s\n"
           "  Total flips    %zu\n", (long)elapsed, flip_total);
    for (int c = 0; c < FLIP_CLASS_COUNT; c++)
        if (counts[c])
            printf("  %-22s %zu\n", flip_class_names[c], counts[c]);
    printf("─────────────────────────────────────────────────────\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Argument Parser
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_args(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--report-url") && i+1 < argc) {
            snprintf(report_url, sizeof(report_url), "%s", argv[++i]);

        } else if (!strcmp(argv[i], "--report-window") && i+1 < argc) {
            long w = parse_report_window(argv[++i]);
            if (w < 0) {
                fprintf(stderr,
                    "[-] Invalid --report-window '%s'\n"
                    "    Examples: 10s  30m  6h  3d\n", argv[i]);
                exit(1);
            }
            opt_report_window = w;

        } else if (!strcmp(argv[i], "--altitude") && i+1 < argc) {
            opt_altitude = atoi(argv[++i]);

        } else if (!strcmp(argv[i], "--interval") && i+1 < argc) {
            opt_interval = atoi(argv[++i]);

        } else if (!strcmp(argv[i], "--help")) {
            printf(
                "Usage: cosmic_rowhammer [OPTIONS]\n\n"
                "  --report-window <time>  Report flush interval (default: 3d)\n"
                "                          Suffixes: s=seconds  m=minutes  h=hours  d=days\n"
                "                          Examples: 10s  30m  6h  2d\n"
                "  --report-url    <url>   POST anonymised JSON report to URL\n"
                "  --altitude      <m>     Altitude in metres (logged in report)\n"
                "  --interval      <s>     Scan interval in seconds (default: %d)\n\n"
                "Examples:\n"
#ifdef _WIN32
                "  .\\cosmic_rowhammer.exe --report-window 10s   # quick test\n"
                "  .\\cosmic_rowhammer.exe --report-window 3d --report-url https://...\n",
#else
                "  sudo ./cosmic_rowhammer --report-window 10s   # quick test\n"
                "  sudo ./cosmic_rowhammer --report-window 3d --report-url https://...\n",
#endif
                SCAN_INTERVAL_S);
            exit(0);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    platform_init_console();
    parse_args(argc, argv);

    signal(SIGINT,  sig_handler);
#ifdef SIGTERM
    signal(SIGTERM, sig_handler);
#endif

    print_banner();

    printf("[*] Allocating 512 MB arena...\n");
    arena = alloc_arena();
    if (!arena) { fprintf(stderr, "[-] Arena allocation failed.\n"); return 1; }
    printf("[+] Arena @ %p\n", (void *)arena);

    printf("[*] Writing sentinel patterns + PTE simulation region...\n");
    fill_arena(arena);
    printf("[+] Arena ready.\n\n");

    time_t start  = time(NULL);
    time_t last_r = start;
    size_t scans  = 0;
    report_win.window_start = start;

    while (running) {
        spray_pass(arena);
        platform_sleep_seconds((unsigned)opt_interval);

        char ts[32]; ts_now(ts, sizeof(ts));
        size_t found = scan_arena(arena);
        scans++;
        report_win.scan_cycles++;

        if (!found) {
            printf("[%s] Scan #%zu — no flips\n", ts, scans);
            fflush(stdout);
        }

        /* Configurable report window */
        if (time(NULL) - last_r >= opt_report_window) {
            emit_report();
            last_r = time(NULL);
        }
    }

    /* Final partial-window report */
    emit_report();
    print_stats(start);

    platform_release_arena(arena);
    printf("[*] Arena released. Goodbye.\n");
    return 0;
}
