#include <cstring>
#include <cerrno>
#include <string>
#include <thread>
#include <ctime>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "hack.h"
#include "zygisk.hpp"
#include "game.h"
#include "log.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        auto process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        auto app_data_dir = env->GetStringUTFChars(args->app_data_dir, nullptr);
        preSpecialize(process_name, app_data_dir);
        env->ReleaseStringUTFChars(args->nice_name, process_name);
        env->ReleaseStringUTFChars(args->app_data_dir, app_data_dir);
    }

    void postAppSpecialize(const AppSpecializeArgs *) override {
        if (enable_hack) {
            writeProofOfLife();
            std::thread hack_thread(hack_prepare, game_data_dir, data, length);
            hack_thread.detach();
        }
    }

private:
    Api *api = nullptr;
    JNIEnv *env = nullptr;
    bool enable_hack = false;
    char *game_data_dir = nullptr;
    char *game_process_name = nullptr;
    void *data = nullptr;
    size_t length = 0;

    static bool fuzzyTargetMatch(const char *process_name) {
        if (!process_name) return false;
        return strstr(process_name, GamePackageName) != nullptr || strstr(process_name, "com.mjhwd") != nullptr;
    }

    static void appendLine(const char *path, const std::string &line) {
        int fd = open(path, O_CREAT | O_APPEND | O_WRONLY, 0664);
        if (fd < 0) {
            LOGW("probe open failed: %s errno=%d", path, errno);
            return;
        }
        (void) write(fd, line.c_str(), line.size());
        close(fd);
    }

    void writeProofOfLife() {
        std::time_t t = std::time(nullptr);
        pid_t pid = getpid();
        std::string proc = game_process_name ? game_process_name : "<null>";

        std::string line = "alive ts=" + std::to_string((long long) t)
                + " pid=" + std::to_string((int) pid)
                + " process=" + proc + "\n";

        appendLine("/storage/emulated/0/Download/zygisk_alive.txt", line);

        if (game_data_dir && *game_data_dir) {
            std::string app_path = std::string(game_data_dir) + "/zygisk_alive.txt";
            appendLine(app_path.c_str(), line);
        } else {
            appendLine("/data/data/com.mjhwd.tt.sdk01/zygisk_alive.txt", line);
        }
        LOGI("probe written pid=%d process=%s", (int) pid, proc.c_str());
    }

    void preSpecialize(const char *process_name, const char *app_data_dir) {
        if (fuzzyTargetMatch(process_name)) {
            LOGI("detect process fuzzy match: %s", process_name);
            enable_hack = true;

            if (app_data_dir) {
                game_data_dir = new char[strlen(app_data_dir) + 1];
                strcpy(game_data_dir, app_data_dir);
            }
            if (process_name) {
                game_process_name = new char[strlen(process_name) + 1];
                strcpy(game_process_name, process_name);
            }

#if defined(__i386__)
            auto path = "zygisk/armeabi-v7a.so";
#endif
#if defined(__x86_64__)
            auto path = "zygisk/arm64-v8a.so";
#endif
#if defined(__i386__) || defined(__x86_64__)
            int dirfd = api->getModuleDir();
            int fd = openat(dirfd, path, O_RDONLY);
            if (fd != -1) {
                struct stat sb{};
                fstat(fd, &sb);
                length = sb.st_size;
                data = mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fd, 0);
                close(fd);
            } else {
                LOGW("Unable to open arm file");
            }
#endif
        } else {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }
};

REGISTER_ZYGISK_MODULE(MyModule)

