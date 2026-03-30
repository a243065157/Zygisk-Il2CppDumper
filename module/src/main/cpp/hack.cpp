#include "hack.h"
#include "log.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dlfcn.h>
#include "xdl/include/xdl.h"
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

namespace {

constexpr const char *kTargetSo = "libxlua.so";
constexpr const char *kFallbackSo = "libil2cpp.so";
constexpr const char *kOutDir = "/sdcard/Download/lua_dump";
constexpr const char *kMapsPath = "/proc/self/maps";
constexpr const char *kProofPath = "/sdcard/Download/zygisk_alive.txt";
constexpr size_t kMaxDumpSize = 8 * 1024 * 1024;
constexpr int kMaxWaitSec = 180;

using luaL_loadbufferx_t = int (*)(void *L, const char *buff, size_t sz, const char *name, const char *mode);
using luaL_loadbuffer_t = int (*)(void *L, const char *buff, size_t sz, const char *name);
using lua_load_t = int (*)(void *L, void *reader, void *data, const char *chunkname, const char *mode);
using lua_pcall_t = int (*)(void *L, int nargs, int nresults, int errfunc);
using lua_pcallk_t = int (*)(void *L, int nargs, int nresults, int errfunc, intptr_t ctx, void *k);
using lua_settop_t = void (*)(void *L, int idx);
using lua_gettop_t = int (*)(void *L);

extern "C" int DobbyHook(void *address, void *replace_call, void **origin_call) __attribute__((weak));
extern "C" int xhook_register(const char *pathname_regex_str, const char *symbol, void *new_func, void **old_func) __attribute__((weak));
extern "C" int xhook_refresh(int async) __attribute__((weak));

luaL_loadbufferx_t g_orig_loadbufferx = nullptr;
luaL_loadbuffer_t g_orig_loadbuffer = nullptr;
lua_load_t g_orig_load = nullptr;
lua_pcall_t g_orig_pcall = nullptr;
lua_pcallk_t g_orig_pcallk = nullptr;
lua_settop_t g_orig_settop = nullptr;
lua_gettop_t g_orig_gettop = nullptr;

std::atomic<uint64_t> g_seq{0};
thread_local bool g_in_dump = false;
std::string g_app_data_dir;

std::atomic<uint32_t> g_hit_loadbufferx{0};
std::atomic<uint32_t> g_hit_loadbuffer{0};
std::atomic<uint32_t> g_hit_load{0};
std::atomic<uint32_t> g_hit_pcall{0};
std::atomic<uint32_t> g_hit_pcallk{0};
std::atomic<uint32_t> g_hit_settop{0};
std::atomic<uint32_t> g_hit_gettop{0};

struct HookSpec {
    const char *symbol;
    void *replacement;
    void **original;
    bool installed = false;
    bool symbol_found = false;
    bool xhook_attempted = false;
    uintptr_t symbol_addr = 0;
    int install_rc = -9999;
    const char *engine = "none";
    const char *reason = "not_attempted";
};

static bool maps_contains(const char *so_name) {
    std::ifstream in(kMapsPath);
    if (!in.is_open()) return false;
    std::string line;
    while (std::getline(in, line)) {
        if (line.find(so_name) != std::string::npos) return true;
    }
    return false;
}

static bool mkdir_if_needed(const std::string &path) {
    if (path.empty()) return false;
    if (access(path.c_str(), F_OK) == 0) return true;
    if (mkdir(path.c_str(), 0775) == 0) return true;
    return errno == EEXIST;
}

static bool mkdirs(const std::string &path) {
    if (path.empty() || path[0] != '/') return false;
    std::string cur;
    for (size_t i = 0; i < path.size(); i++) {
        cur.push_back(path[i]);
        if (path[i] == '/' && cur.size() > 1) {
            if (!mkdir_if_needed(cur.substr(0, cur.size() - 1))) return false;
        }
    }
    return mkdir_if_needed(path);
}

static void append_line(const char *path, const std::string &line) {
    int fd = open(path, O_CREAT | O_APPEND | O_WRONLY, 0664);
    if (fd < 0) return;
    (void) write(fd, line.c_str(), line.size());
    close(fd);
}

static void write_status(const std::string &line) {
    append_line(kProofPath, line + "\n");
    if (!g_app_data_dir.empty()) {
        append_line((g_app_data_dir + "/zygisk_alive.txt").c_str(), line + "\n");
    }
}

static std::string sanitize_name(const char *name, const char *fallback_prefix) {
    std::string out;
    if (name && *name) out = name;
    if (!out.empty() && out[0] == '@') out.erase(0, 1);
    for (char &c : out) {
        if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') c = '_';
        if (static_cast<unsigned char>(c) < 0x20) c = '_';
    }
    if (out.empty()) out = std::string(fallback_prefix) + "_" + std::to_string(g_seq.fetch_add(1)) + ".lua";
    if (out.size() > 180) out.resize(180);
    return out;
}

static void record_hit(const char *api, std::atomic<uint32_t> &counter, const std::string &detail, uint32_t cap) {
    const uint32_t n = ++counter;
    if (n <= cap) {
        const std::string line = std::string("hit ") + api + " count=" + std::to_string(n) + " " + detail;
        write_status(line);
        LOGI("%s", line.c_str());
    }
}

static void write_chunk(const char *api, const char *buff, size_t sz, const char *name) {
    if (g_in_dump) return;
    if (!buff || sz == 0 || sz > kMaxDumpSize) return;

    g_in_dump = true;

    if (!mkdirs(kOutDir)) {
        LOGE("lua_dump mkdirs failed: %s", kOutDir);
        write_status("lua_dump mkdirs failed");
        g_in_dump = false;
        return;
    }

    const std::string file_name = sanitize_name(name, api);
    const std::string out_path = std::string(kOutDir) + "/" + file_name;

    int fd = open(out_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0664);
    if (fd < 0) {
        LOGE("lua_dump open failed: %s errno=%d", out_path.c_str(), errno);
        write_status("lua_dump open failed errno=" + std::to_string(errno));
        g_in_dump = false;
        return;
    }

    ssize_t wr = write(fd, buff, sz);
    close(fd);
    if (wr != static_cast<ssize_t>(sz)) {
        LOGE("lua_dump write short: %s want=%zu got=%zd", out_path.c_str(), sz, wr);
        write_status("lua_dump write short");
        g_in_dump = false;
        return;
    }

    LOGI("lua_dump ok api=%s size=%zu name=%s", api, sz, file_name.c_str());
    write_status(std::string("lua_dump ok api=") + api + " size=" + std::to_string(sz) + " name=" + file_name);
    g_in_dump = false;
}

#if defined(__aarch64__)

static inline uintptr_t page_start(uintptr_t x) {
    const uintptr_t ps = static_cast<uintptr_t>(sysconf(_SC_PAGESIZE));
    return x & ~(ps - 1);
}

static bool make_writable_exec(void *addr, size_t len) {
    uintptr_t start = page_start(reinterpret_cast<uintptr_t>(addr));
    uintptr_t end = page_start(reinterpret_cast<uintptr_t>(addr) + len - 1) + static_cast<uintptr_t>(sysconf(_SC_PAGESIZE));
    size_t span = end - start;
    return mprotect(reinterpret_cast<void *>(start), span, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

static void write_abs_jump(void *from, void *to) {
    uint32_t insn1 = 0x58000051;
    uint32_t insn2 = 0xD61F0220;
    std::memcpy(from, &insn1, sizeof(insn1));
    std::memcpy(reinterpret_cast<uint8_t *>(from) + 4, &insn2, sizeof(insn2));
    std::memcpy(reinterpret_cast<uint8_t *>(from) + 8, &to, sizeof(to));
    __builtin___clear_cache(reinterpret_cast<char *>(from), reinterpret_cast<char *>(from) + 16);
}

static bool install_inline_hook(void *target, void *replacement, void **original) {
    if (!target || !replacement || !original) return false;

    void *trampoline = mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trampoline == MAP_FAILED) {
        LOGE("mmap trampoline failed errno=%d", errno);
        return false;
    }

    std::memcpy(trampoline, target, 16);
    write_abs_jump(reinterpret_cast<uint8_t *>(trampoline) + 16,
                   reinterpret_cast<uint8_t *>(target) + 16);

    if (!make_writable_exec(target, 16)) {
        LOGE("mprotect target failed errno=%d", errno);
        munmap(trampoline, 0x1000);
        return false;
    }

    write_abs_jump(target, replacement);
    *original = reinterpret_cast<void *>(reinterpret_cast<uint8_t *>(trampoline));
    return true;
}

#else

static bool install_inline_hook(void *target, void *replacement, void **original) {
    (void) target;
    (void) replacement;
    (void) original;
    LOGE("inline hook only implemented for arm64");
    return false;
}

#endif

static bool try_xhook(HookSpec &spec) {
    if (!xhook_register || !xhook_refresh) {
        spec.engine = "xhook";
        spec.reason = "xhook_unavailable";
        spec.install_rc = -1001;
        return false;
    }

    int rc1 = xhook_register(".*libxlua\\\\.so$", spec.symbol, spec.replacement, spec.original);
    int rc2 = xhook_register(".*libil2cpp\\\\.so$", spec.symbol, spec.replacement, spec.original);
    int rc3 = xhook_refresh(0);

    if ((rc1 == 0 || rc2 == 0) && rc3 == 0) {
        spec.engine = "xhook";
        spec.reason = "ok";
        spec.install_rc = 0;
        return true;
    }

    spec.engine = "xhook";
    spec.reason = "xhook_failed";
    spec.install_rc = (rc1 != 0) ? rc1 : ((rc2 != 0) ? rc2 : rc3);
    return false;
}

static bool install_hook(void *sym, HookSpec &spec) {
    spec.reason = "symbol_not_found";

    if (!sym) {
        spec.install_rc = -2;
        return false;
    }

    if (DobbyHook) {
        int rc = DobbyHook(sym, spec.replacement, spec.original);
        if (rc == 0) {
            spec.engine = "dobby";
            spec.reason = "ok";
            spec.install_rc = 0;
            return true;
        }
        spec.engine = "dobby";
        spec.reason = "dobby_failed";
        spec.install_rc = rc;
    }

    if (install_inline_hook(sym, spec.replacement, spec.original)) {
        spec.engine = "inline";
        spec.reason = "ok";
        spec.install_rc = 0;
        return true;
    }

    spec.engine = DobbyHook ? "dobby+inline" : "inline";
    spec.reason = "install_failed";
    if (spec.install_rc == -9999) spec.install_rc = -3;
    return false;
}

static int hook_luaL_loadbufferx(void *L, const char *buff, size_t sz, const char *name, const char *mode) {
    (void) mode;
    record_hit("luaL_loadbufferx", g_hit_loadbufferx,
               std::string("size=") + std::to_string(sz) + " name=" + (name ? name : "<null>"), 6);
    write_chunk("luaL_loadbufferx", buff, sz, name);
    if (g_orig_loadbufferx) return g_orig_loadbufferx(L, buff, sz, name, mode);
    return 0;
}

static int hook_luaL_loadbuffer(void *L, const char *buff, size_t sz, const char *name) {
    record_hit("luaL_loadbuffer", g_hit_loadbuffer,
               std::string("size=") + std::to_string(sz) + " name=" + (name ? name : "<null>"), 6);
    write_chunk("luaL_loadbuffer", buff, sz, name);
    if (g_orig_loadbuffer) return g_orig_loadbuffer(L, buff, sz, name);
    return 0;
}

static int hook_lua_load(void *L, void *reader, void *data, const char *chunkname, const char *mode) {
    record_hit("lua_load", g_hit_load,
               std::string("reader=") + std::to_string(reinterpret_cast<uintptr_t>(reader)) +
               " chunk=" + (chunkname ? chunkname : "<null>") +
               " mode=" + (mode ? mode : "<null>"), 8);
    if (g_orig_load) return g_orig_load(L, reader, data, chunkname, mode);
    return 0;
}

static int hook_lua_pcall(void *L, int nargs, int nresults, int errfunc) {
    record_hit("lua_pcall", g_hit_pcall,
               "nargs=" + std::to_string(nargs) + " nresults=" + std::to_string(nresults) + " err=" + std::to_string(errfunc), 8);
    if (g_orig_pcall) return g_orig_pcall(L, nargs, nresults, errfunc);
    return 0;
}

static int hook_lua_pcallk(void *L, int nargs, int nresults, int errfunc, intptr_t ctx, void *k) {
    record_hit("lua_pcallk", g_hit_pcallk,
               "nargs=" + std::to_string(nargs) + " nresults=" + std::to_string(nresults) +
               " err=" + std::to_string(errfunc) + " ctx=" + std::to_string(static_cast<long long>(ctx)) +
               " k=" + std::to_string(reinterpret_cast<uintptr_t>(k)), 8);
    if (g_orig_pcallk) return g_orig_pcallk(L, nargs, nresults, errfunc, ctx, k);
    return 0;
}

static void hook_lua_settop(void *L, int idx) {
    record_hit("lua_settop", g_hit_settop, "idx=" + std::to_string(idx), 4);
    if (g_orig_settop) g_orig_settop(L, idx);
}

static int hook_lua_gettop(void *L) {
    record_hit("lua_gettop", g_hit_gettop, "", 4);
    if (g_orig_gettop) return g_orig_gettop(L);
    return 0;
}

static void report_final_status(const HookSpec &spec) {
    if (spec.installed) {
        write_status(std::string("Hook ") + spec.symbol + " status: OK engine=" + spec.engine +
                     " addr=0x" + std::to_string(static_cast<unsigned long long>(spec.symbol_addr)));
        return;
    }
    if (!spec.symbol_found) {
        write_status(std::string("Hook ") + spec.symbol + " status: FAILED (Symbol not found)");
        return;
    }
    write_status(std::string("Hook ") + spec.symbol + " status: FAILED engine=" + spec.engine +
                 " rc=" + std::to_string(spec.install_rc) + " reason=" + spec.reason);
}

static void run_lua_dump_hook() {
    void *handle_xlua = nullptr;
    void *handle_il2cpp = nullptr;
    void *xdl_xlua = nullptr;
    void *xdl_il2cpp = nullptr;

    HookSpec specs[] = {
            {"luaL_loadbufferx", reinterpret_cast<void *>(hook_luaL_loadbufferx), reinterpret_cast<void **>(&g_orig_loadbufferx)},
            {"luaL_loadbuffer", reinterpret_cast<void *>(hook_luaL_loadbuffer), reinterpret_cast<void **>(&g_orig_loadbuffer)},
            {"lua_load", reinterpret_cast<void *>(hook_lua_load), reinterpret_cast<void **>(&g_orig_load)},
            {"lua_pcall", reinterpret_cast<void *>(hook_lua_pcall), reinterpret_cast<void **>(&g_orig_pcall)},
            {"lua_pcallk", reinterpret_cast<void *>(hook_lua_pcallk), reinterpret_cast<void **>(&g_orig_pcallk)},
            {"lua_settop", reinterpret_cast<void *>(hook_lua_settop), reinterpret_cast<void **>(&g_orig_settop)},
            {"lua_gettop", reinterpret_cast<void *>(hook_lua_gettop), reinterpret_cast<void **>(&g_orig_gettop)},
    };

    write_status("lua hook wait start targets=libxlua.so,libil2cpp.so");
    LOGI("lua hook wait start targets=%s,%s", kTargetSo, kFallbackSo);

    bool xhook_noted = false;
    if (!xhook_register || !xhook_refresh) {
        xhook_noted = true;
        write_status("xhook status: unavailable (not linked)");
    }

    for (int i = 0; i < kMaxWaitSec * 2; i++) {
        if (!handle_xlua && maps_contains(kTargetSo)) {
            handle_xlua = dlopen(kTargetSo, RTLD_NOW);
            if (!xdl_xlua) xdl_xlua = xdl_open(kTargetSo, XDL_DEFAULT);
            LOGI("target seen: %s handle=%p", kTargetSo, handle_xlua);
            write_status(std::string("target seen: ") + kTargetSo + " handle=" + std::to_string(reinterpret_cast<uintptr_t>(handle_xlua)));
        }

        if (!handle_il2cpp && maps_contains(kFallbackSo)) {
            handle_il2cpp = dlopen(kFallbackSo, RTLD_NOW);
            if (!xdl_il2cpp) xdl_il2cpp = xdl_open(kFallbackSo, XDL_DEFAULT);
            LOGI("target seen: %s handle=%p", kFallbackSo, handle_il2cpp);
            write_status(std::string("target seen: ") + kFallbackSo + " handle=" + std::to_string(reinterpret_cast<uintptr_t>(handle_il2cpp)));
        }

        if (!xhook_noted && (handle_xlua || handle_il2cpp)) {
            xhook_noted = true;
            write_status("xhook status: available (linked), strategy=try xhook then dobby/inline");
        }

        int installed_count = 0;
        for (auto &spec : specs) {
            if (spec.installed) {
                installed_count++;
                continue;
            }

            if (!spec.xhook_attempted && (handle_xlua || handle_il2cpp)) {
                spec.xhook_attempted = true;
                if (try_xhook(spec)) {
                    spec.installed = true;
                    installed_count++;
                    write_status(std::string("hook installed: ") + spec.symbol + " engine=xhook");
                    continue;
                }
            }

            void *sym = nullptr;
            if (xdl_xlua) sym = xdl_sym(xdl_xlua, spec.symbol, nullptr);
            if (!sym && xdl_il2cpp) sym = xdl_sym(xdl_il2cpp, spec.symbol, nullptr);
            if (!sym && handle_xlua) sym = dlsym(handle_xlua, spec.symbol);
            if (!sym && handle_il2cpp) sym = dlsym(handle_il2cpp, spec.symbol);
            if (!sym) sym = dlsym(RTLD_DEFAULT, spec.symbol);

            if (!sym) {
                continue;
            }

            spec.symbol_found = true;
            spec.symbol_addr = reinterpret_cast<uintptr_t>(sym);
            if (install_hook(sym, spec)) {
                spec.installed = true;
                installed_count++;
                const std::string ok = std::string("hook installed: ") + spec.symbol +
                                       " engine=" + spec.engine +
                                       " target=" + std::to_string(reinterpret_cast<uintptr_t>(sym));
                LOGI("%s", ok.c_str());
                write_status(ok);
            }
        }

        if (installed_count == static_cast<int>(sizeof(specs) / sizeof(specs[0]))) {
            write_status("lua hook armed: all targets installed");
            return;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    LOGE("lua hook timeout, symbol install not complete");
    write_status("lua hook timeout, symbol install not complete");

    for (const auto &spec : specs) {
        report_final_status(spec);
    }

    if (xdl_xlua) xdl_close(xdl_xlua);
    if (xdl_il2cpp) xdl_close(xdl_il2cpp);
}

} // namespace

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    (void) data;
    (void) length;
    if (game_data_dir && *game_data_dir) {
        g_app_data_dir = game_data_dir;
    } else {
        g_app_data_dir.clear();
    }
    LOGI("lua dump hook thread start pid=%d", getpid());
    write_status(std::string("lua dump hook thread start pid=") + std::to_string(getpid()));
    run_lua_dump_hook();
}










