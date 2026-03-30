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
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>

namespace {

constexpr const char *kTargetSo = "libxlua.so";
constexpr const char *kFallbackSo = "libil2cpp.so";
constexpr const char *kOutDir = "/sdcard/Download/lua_dump";
constexpr const char *kMapsPath = "/proc/self/maps";
constexpr size_t kMaxDumpSize = 8 * 1024 * 1024;
constexpr int kMaxWaitSec = 180;

using luaL_loadbufferx_t = int (*)(void *L, const char *buff, size_t sz, const char *name, const char *mode);
using luaL_loadbuffer_t = int (*)(void *L, const char *buff, size_t sz, const char *name);

luaL_loadbufferx_t g_orig_loadbufferx = nullptr;
luaL_loadbuffer_t g_orig_loadbuffer = nullptr;

std::atomic<uint64_t> g_seq{0};
thread_local bool g_in_dump = false;

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

static void write_chunk(const char *api, const char *buff, size_t sz, const char *name) {
    if (g_in_dump) return;
    if (!buff || sz == 0 || sz > kMaxDumpSize) return;

    g_in_dump = true;

    if (!mkdirs(kOutDir)) {
        LOGE("lua_dump mkdirs failed: %s", kOutDir);
        g_in_dump = false;
        return;
    }

    const std::string file_name = sanitize_name(name, api);
    const std::string out_path = std::string(kOutDir) + "/" + file_name;

    int fd = open(out_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0664);
    if (fd < 0) {
        LOGE("lua_dump open failed: %s errno=%d", out_path.c_str(), errno);
        g_in_dump = false;
        return;
    }

    ssize_t wr = write(fd, buff, sz);
    close(fd);
    if (wr != static_cast<ssize_t>(sz)) {
        LOGE("lua_dump write short: %s want=%zu got=%zd", out_path.c_str(), sz, wr);
        g_in_dump = false;
        return;
    }

    LOGI("lua_dump ok api=%s size=%zu name=%s", api, sz, file_name.c_str());
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

static int hook_luaL_loadbufferx(void *L, const char *buff, size_t sz, const char *name, const char *mode) {
    write_chunk("luaL_loadbufferx", buff, sz, name);
    if (g_orig_loadbufferx) return g_orig_loadbufferx(L, buff, sz, name, mode);
    return 0;
}

static int hook_luaL_loadbuffer(void *L, const char *buff, size_t sz, const char *name) {
    write_chunk("luaL_loadbuffer", buff, sz, name);
    if (g_orig_loadbuffer) return g_orig_loadbuffer(L, buff, sz, name);
    return 0;
}

static void run_lua_dump_hook() {
    void *handle_xlua = nullptr;
    void *handle_il2cpp = nullptr;
    bool loadbufferx_installed = false;
    bool loadbuffer_installed = false;

    LOGI("lua hook wait start targets=%s,%s", kTargetSo, kFallbackSo);

    for (int i = 0; i < kMaxWaitSec * 2; i++) {
        if (!handle_xlua && maps_contains(kTargetSo)) {
            handle_xlua = dlopen(kTargetSo, RTLD_NOW);
            LOGI("target seen: %s handle=%p", kTargetSo, handle_xlua);
        }

        if (!handle_il2cpp && maps_contains(kFallbackSo)) {
            handle_il2cpp = dlopen(kFallbackSo, RTLD_NOW);
            LOGI("target seen: %s handle=%p", kFallbackSo, handle_il2cpp);
        }

        if (!loadbufferx_installed) {
            void *sym_x = nullptr;
            if (handle_xlua) sym_x = dlsym(handle_xlua, "luaL_loadbufferx");
            if (!sym_x && handle_il2cpp) sym_x = dlsym(handle_il2cpp, "luaL_loadbufferx");
            if (sym_x) {
                void *orig = nullptr;
                if (install_inline_hook(sym_x, reinterpret_cast<void *>(hook_luaL_loadbufferx), &orig)) {
                    g_orig_loadbufferx = reinterpret_cast<luaL_loadbufferx_t>(orig);
                    loadbufferx_installed = true;
                    LOGI("hook installed: luaL_loadbufferx target=%p tramp=%p", sym_x, orig);
                } else {
                    LOGE("hook install failed: luaL_loadbufferx");
                }
            }
        }

        if (!loadbuffer_installed) {
            void *sym = nullptr;
            if (handle_xlua) sym = dlsym(handle_xlua, "luaL_loadbuffer");
            if (!sym && handle_il2cpp) sym = dlsym(handle_il2cpp, "luaL_loadbuffer");
            if (sym) {
                void *orig = nullptr;
                if (install_inline_hook(sym, reinterpret_cast<void *>(hook_luaL_loadbuffer), &orig)) {
                    g_orig_loadbuffer = reinterpret_cast<luaL_loadbuffer_t>(orig);
                    loadbuffer_installed = true;
                    LOGI("hook installed: luaL_loadbuffer target=%p tramp=%p", sym, orig);
                } else {
                    LOGE("hook install failed: luaL_loadbuffer");
                }
            }
        }

        if (loadbufferx_installed || loadbuffer_installed) {
            LOGI("lua hook armed loadbufferx=%d loadbuffer=%d", loadbufferx_installed ? 1 : 0, loadbuffer_installed ? 1 : 0);
            return;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    LOGE("lua hook timeout, no symbol found in %s/%s", kTargetSo, kFallbackSo);
}

} // namespace

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    (void) game_data_dir;
    (void) data;
    (void) length;
    LOGI("lua dump hook thread start pid=%d", getpid());
    run_lua_dump_hook();
}
