#include "hack.h"
#include "log.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <set>
#include <string>
#include <sys/syscall.h>
#include <thread>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr const char *kOutRoot = "/sdcard/Download/unified_dump";
constexpr const char *kMapsPath = "/proc/self/maps";
constexpr const char *kTargetSo = "libil2cpp.so";
constexpr int kMaxWaitSec = 45;
constexpr size_t kChunkSize = 0x20000;

// 当前已验证的高概率候选 RVA（同会话下转换为绝对地址后用于定位所在内存段）。
constexpr std::array<uint64_t, 5> kCodeRvas = {
        0x2C21420, 0x2C21428, 0x2C21430, 0x2C21438, 0x2C21440
};
constexpr std::array<uint64_t, 5> kMetaRvas = {
        0x2C4A0E0, 0x2C4A100, 0x2C4A120, 0x2C4A140, 0x2C4A160
};

struct MapEntry {
    uint64_t start = 0;
    uint64_t end = 0;
    std::string perms;
    uint64_t offset = 0;
    std::string path;
};

static bool starts_with(const std::string &s, const char *prefix) {
    return s.rfind(prefix, 0) == 0;
}

static std::string trim(const std::string &s) {
    size_t l = 0;
    while (l < s.size() && (s[l] == ' ' || s[l] == '\t' || s[l] == '\n' || s[l] == '\r')) l++;
    size_t r = s.size();
    while (r > l && (s[r - 1] == ' ' || s[r - 1] == '\t' || s[r - 1] == '\n' || s[r - 1] == '\r')) r--;
    return s.substr(l, r - l);
}

static bool mkdir_if_needed(const std::string &path) {
    if (path.empty()) return false;
    if (access(path.c_str(), F_OK) == 0) return true;
    if (mkdir(path.c_str(), 0775) == 0) return true;
    return errno == EEXIST;
}

static bool mkdirs(const std::string &path) {
    if (path.empty()) return false;
    if (path[0] != '/') return false;

    std::string cur;
    for (size_t i = 0; i < path.size(); i++) {
        cur.push_back(path[i]);
        if (path[i] == '/' && cur.size() > 1) {
            if (!mkdir_if_needed(cur.substr(0, cur.size() - 1))) return false;
        }
    }
    return mkdir_if_needed(path);
}

static std::string now_tag() {
    auto t = std::time(nullptr);
    struct tm tmv{};
    localtime_r(&t, &tmv);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d%02d%02d_%02d%02d%02d",
                  tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                  tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return std::string(buf);
}

static bool parse_maps(std::vector<MapEntry> &out) {
    FILE *fp = std::fopen(kMapsPath, "re");
    if (!fp) return false;

    char line[2048];
    while (std::fgets(line, sizeof(line), fp)) {
        uint64_t start = 0, end = 0, off = 0;
        char perms[8] = {0};
        char dev[16] = {0};
        unsigned long inode = 0;
        int consumed = 0;

        int n = std::sscanf(line, "%" SCNx64 "-%" SCNx64 " %7s %" SCNx64 " %15s %lu %n",
                            &start, &end, perms, &off, dev, &inode, &consumed);
        if (n < 6) continue;

        std::string path;
        if (consumed > 0 && consumed < (int) std::strlen(line)) {
            path = trim(std::string(line + consumed));
        }

        MapEntry e;
        e.start = start;
        e.end = end;
        e.perms = perms;
        e.offset = off;
        e.path = path;
        out.push_back(std::move(e));
    }
    std::fclose(fp);

    std::sort(out.begin(), out.end(), [](const MapEntry &a, const MapEntry &b) {
        return a.start < b.start;
    });
    return !out.empty();
}

static bool find_libil2cpp_base(const std::vector<MapEntry> &maps, uint64_t &base_out) {
    bool found = false;
    uint64_t min_addr = UINT64_MAX;
    for (const auto &e : maps) {
        if (e.path.find(kTargetSo) == std::string::npos) continue;
        if (e.start < min_addr) {
            min_addr = e.start;
            found = true;
        }
    }
    if (found) base_out = min_addr;
    return found;
}

static const MapEntry *find_segment_containing(const std::vector<MapEntry> &maps, uint64_t addr) {
    for (const auto &e : maps) {
        if (e.start <= addr && addr < e.end) {
            return &e;
        }
    }
    return nullptr;
}

static std::string seg_label(const MapEntry &e) {
    char buf[256];
    std::snprintf(buf, sizeof(buf), "%" PRIx64 "-%" PRIx64 "_%s",
                  e.start, e.end, e.perms.c_str());
    return std::string(buf);
}

static ssize_t read_self_vm(uint64_t remote_addr, void *buf, size_t len) {
    iovec local_iov{};
    local_iov.iov_base = buf;
    local_iov.iov_len = len;

    iovec remote_iov{};
    remote_iov.iov_base = reinterpret_cast<void *>(remote_addr);
    remote_iov.iov_len = len;

    return syscall(__NR_process_vm_readv, getpid(), &local_iov, 1, &remote_iov, 1, 0);
}

static bool dump_segment_via_vmread(const MapEntry &seg, const std::string &out_path, uint64_t &read_ok, uint64_t &read_fail) {
    int out_fd = open(out_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0664);
    if (out_fd < 0) return false;

    std::vector<char> buf(kChunkSize);
    uint64_t cur = seg.start;
    read_ok = 0;
    read_fail = 0;

    while (cur < seg.end) {
        size_t want = (size_t) std::min<uint64_t>(kChunkSize, seg.end - cur);
        ssize_t got = read_self_vm(cur, buf.data(), want);
        if (got > 0) {
            ssize_t wr = write(out_fd, buf.data(), (size_t) got);
            if (wr != got) {
                close(out_fd);
                return false;
            }
            read_ok += (uint64_t) got;
            cur += (uint64_t) got;
        } else {
            // 不可读页面补零，保持文件与 VA 区间长度一致。
            std::memset(buf.data(), 0, want);
            ssize_t wr = write(out_fd, buf.data(), want);
            if (wr != (ssize_t) want) {
                close(out_fd);
                return false;
            }
            read_fail += want;
            cur += want;
        }
    }

    close(out_fd);
    return true;
}

static void run_unified_capture() {
    std::vector<MapEntry> maps;

    uint64_t runtime_base = 0;
    bool loaded = false;
    for (int i = 0; i < kMaxWaitSec; i++) {
        maps.clear();
        if (parse_maps(maps) && find_libil2cpp_base(maps, runtime_base)) {
            loaded = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    const int pid = getpid();
    const std::string session = std::string(kOutRoot) + "/session_" + now_tag() + "_pid" + std::to_string(pid);
    if (!mkdirs(std::string(kOutRoot)) || !mkdirs(session)) {
        LOGE("mkdirs failed: %s", session.c_str());
        return;
    }

    const std::string reg_path = session + "/reg.txt";
    FILE *reg = std::fopen(reg_path.c_str(), "we");
    if (!reg) {
        LOGE("open reg file failed: %s", reg_path.c_str());
        return;
    }

    std::fprintf(reg, "status=%s\n", loaded ? "loaded" : "timeout");
    std::fprintf(reg, "pid=%d\n", pid);
    if (!loaded) {
        std::fclose(reg);
        return;
    }

    std::fprintf(reg, "runtime_base=0x%" PRIx64 "\n", runtime_base);

    std::array<uint64_t, 5> code_abs{};
    std::array<uint64_t, 5> meta_abs{};
    for (size_t i = 0; i < kCodeRvas.size(); i++) {
        code_abs[i] = runtime_base + kCodeRvas[i];
        meta_abs[i] = runtime_base + kMetaRvas[i];
        std::fprintf(reg, "code[%zu].rva=0x%" PRIx64 " abs=0x%" PRIx64 "\n", i, kCodeRvas[i], code_abs[i]);
        std::fprintf(reg, "meta[%zu].rva=0x%" PRIx64 " abs=0x%" PRIx64 "\n", i, kMetaRvas[i], meta_abs[i]);
    }

    // 选取需要转储的段：libil2cpp 全段 + 包含 code/meta 候选地址的段。
    std::set<uint64_t> selected_starts;
    std::vector<std::pair<MapEntry, std::string>> selected;

    for (const auto &e : maps) {
        if (e.path.find(kTargetSo) != std::string::npos) {
            if (selected_starts.insert(e.start).second) {
                selected.push_back({e, "libil2cpp"});
            }
        }
    }

    for (size_t i = 0; i < code_abs.size(); i++) {
        const auto *seg = find_segment_containing(maps, code_abs[i]);
        if (seg && selected_starts.insert(seg->start).second) {
            selected.push_back({*seg, "code_abs[" + std::to_string(i) + "]"});
        }
    }
    for (size_t i = 0; i < meta_abs.size(); i++) {
        const auto *seg = find_segment_containing(maps, meta_abs[i]);
        if (seg && selected_starts.insert(seg->start).second) {
            selected.push_back({*seg, "meta_abs[" + std::to_string(i) + "]"});
        }
    }

    std::sort(selected.begin(), selected.end(), [](const auto &a, const auto &b) {
        return a.first.start < b.first.start;
    });

    const std::string maps_sel_path = session + "/maps_selected.txt";
    FILE *maps_sel = std::fopen(maps_sel_path.c_str(), "we");
    if (!maps_sel) {
        std::fclose(reg);
        LOGE("open maps_selected failed");
        return;
    }

    std::fprintf(maps_sel, "# selected_segments=%zu\n", selected.size());
    for (size_t i = 0; i < selected.size(); i++) {
        const auto &e = selected[i].first;
        std::fprintf(maps_sel,
                     "%zu start=0x%" PRIx64 " end=0x%" PRIx64 " size=0x%" PRIx64 " perms=%s off=0x%" PRIx64 " reason=%s path=%s\n",
                     i,
                     e.start,
                     e.end,
                     (e.end - e.start),
                     e.perms.c_str(),
                     e.offset,
                     selected[i].second.c_str(),
                     e.path.c_str());
    }


    for (size_t i = 0; i < selected.size(); i++) {
        const auto &e = selected[i].first;
        if (e.perms.empty() || e.perms[0] != 'r') {
            std::fprintf(reg, "dump[%zu].skip=unreadable perms=%s start=0x%" PRIx64 "\n", i, e.perms.c_str(), e.start);
            continue;
        }

        const std::string out_name = session + "/dump_" + std::to_string(i) + "_" + seg_label(e) + ".bin";
        uint64_t ok = 0, fail = 0;
        bool dumped = dump_segment_via_vmread(e, out_name, ok, fail);
        std::fprintf(reg,
                     "dump[%zu].ok=%s start=0x%" PRIx64 " end=0x%" PRIx64 " bytes_ok=0x%" PRIx64 " bytes_fail=0x%" PRIx64 " file=%s\n",
                     i,
                     dumped ? "true" : "false",
                     e.start,
                     e.end,
                     ok,
                     fail,
                     out_name.c_str());
    }

    std::fclose(maps_sel);
    std::fprintf(reg, "session_dir=%s\n", session.c_str());
    std::fclose(reg);
    LOGI("unified capture done: %s", session.c_str());
}

} // namespace

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    (void) game_data_dir;
    (void) data;
    (void) length;
    LOGI("unified capture thread start tid=%d", gettid());
    run_unified_capture();
}








