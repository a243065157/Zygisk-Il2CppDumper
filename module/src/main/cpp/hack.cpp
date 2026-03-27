#include "hack.h"
#include "log.h"
#include <array>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <unistd.h>

namespace {

constexpr const char *kOutputPath = "/sdcard/Download/reg.txt";
constexpr const char *kTargetSo = "libil2cpp.so";
constexpr int kMaxWaitSec = 45;

// 基于当前项目已验证过的候选 RVA，做最小读取并落盘供离线比对。
constexpr std::array<uint64_t, 5> kCodeRvas = {
        0x2C21420, 0x2C21428, 0x2C21430, 0x2C21438, 0x2C21440
};
constexpr std::array<uint64_t, 5> kMetaRvas = {
        0x2C4A0E0, 0x2C4A100, 0x2C4A120, 0x2C4A140, 0x2C4A160
};

bool find_libil2cpp_base(uint64_t &base_out) {
    FILE *fp = fopen("/proc/self/maps", "re");
    if (!fp) {
        return false;
    }
    char line[1024];
    bool found = false;
    uint64_t min_addr = UINT64_MAX;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, kTargetSo) == nullptr) {
            continue;
        }
        uint64_t start = 0;
        if (sscanf(line, "%" PRIx64 "-", &start) == 1) {
            if (start < min_addr) {
                min_addr = start;
                found = true;
            }
        }
    }
    fclose(fp);
    if (found) {
        base_out = min_addr;
    }
    return found;
}

void write_line(FILE *out, const char *key, uint64_t value) {
    fprintf(out, "%s=0x%" PRIx64 "\n", key, value);
}

void dump_candidates(FILE *out, const char *name, const std::array<uint64_t, 5> &rvas, uint64_t base) {
    for (size_t i = 0; i < rvas.size(); i++) {
        const uint64_t abs = base + rvas[i];
        uint64_t first_qword = 0;
        memcpy(&first_qword, reinterpret_cast<void *>(abs), sizeof(first_qword));
        fprintf(out, "%s[%zu].rva=0x%" PRIx64 " abs=0x%" PRIx64 " qword=0x%" PRIx64 "\n",
                name, i, rvas[i], abs, first_qword);
    }
}

void reggrab_start() {
    uint64_t base = 0;
    bool loaded = false;
    for (int i = 0; i < kMaxWaitSec; i++) {
        if (find_libil2cpp_base(base)) {
            loaded = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    FILE *out = fopen(kOutputPath, "we");
    if (!out) {
        LOGE("open %s failed: %d", kOutputPath, errno);
        return;
    }

    fprintf(out, "status=%s\n", loaded ? "loaded" : "timeout");
    fprintf(out, "pid=%d\n", getpid());
    if (!loaded) {
        fclose(out);
        return;
    }

    write_line(out, "runtime_base", base);
    dump_candidates(out, "code", kCodeRvas, base);
    dump_candidates(out, "meta", kMetaRvas, base);
    fclose(out);
    LOGI("reggrab done: %s", kOutputPath);
}

} // namespace

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    (void) game_data_dir;
    (void) data;
    (void) length;
    LOGI("reggrab thread start tid=%d", gettid());
    reggrab_start();
}
