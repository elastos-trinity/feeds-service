/*
 * Copyright (c) 2020 trinity-tech
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <memory>
#include <iostream>

#include <CommandHandler.hpp>
#include <DataBase.hpp>
#include <MassDataManager.hpp>
#include <Platform.hpp>

extern "C" {
#define new fix_cpp_keyword_new
#include <carrier.h>
#include <crystal.h>

#include "feeds.h"
#include "auth.h"
#include "msgq.h"
#include "cfg.h"
#include "did.h"
#include "rpc.h"
#include "db.h"
#include "ver.h"
#undef new

size_t connecting_clients;
Carrier *carrier;
}

#define TAG_MAIN "[Feedsd.Main]: "

static const char *resolver = "https://api.elastos.io/did";
std::shared_ptr<Carrier> carrier_instance;

static std::atomic<bool> stop;

static void transport_deinit();

static
void on_receiving_message(Carrier *c, const char *from,
                          const void *msg, size_t len, int64_t timestamp,
                          bool offline, void *context)
{
    (void)offline;
    (void)context;

    vlogD(TAG_MAIN "received message: %s", msg);
    auto msgptr = reinterpret_cast<uint8_t*>(const_cast<void*>(msg));
    auto data = std::vector<uint8_t>(msgptr, msgptr + len);
    std::ignore = trinity::CommandHandler::GetInstance()->received(from, data);
}

static
void idle_callback(Carrier *c, void *context)
{
    (void)c;
    (void)context;

    if (stop) {
        transport_deinit();
        return;
    }

    auth_expire_login();
}

static
void on_connection_status(Carrier *carrier,
                          CarrierConnectionStatus status, void *context)
{
    vlogI(TAG_MAIN "carrier %s", status == CarrierConnectionStatus_Connected ?
                                "connected" : "disconnected");
    if(status != CarrierConnectionStatus_Connected)
            trinity::MassDataManager::GetInstance()->clearAllDataPipe();
}

static
void friend_connection_callback(Carrier *c, const char *friend_id,
                                CarrierConnectionStatus status, void *context)
{
    (void)c;
    (void)context;

    vlogI(TAG_MAIN "[%s] %s", friend_id, status == CarrierConnectionStatus_Connected ?
                                "connected" : "disconnected");

    if (status == CarrierConnectionStatus_Connected) {
        ++connecting_clients;
        return;
    } else
        trinity::MassDataManager::GetInstance()->removeDataPipe(friend_id);

    --connecting_clients;
    feeds_deactivate_suber(friend_id);
    msgq_peer_offline(friend_id);
}

static
void friend_request_callback(Carrier *c, const char *user_id,
                             const CarrierUserInfo *info, const char *hello,
                             void *context)
{
    (void)info;
    (void)hello;
    (void)context;

    vlogI(TAG_MAIN "Received friend request from [%s]", user_id);
    carrier_accept_friend(c, user_id);
}

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>

static
int sys_coredump_set(bool enable)
{
    const struct rlimit rlim = {
        enable ? RLIM_INFINITY : 0,
        enable ? RLIM_INFINITY : 0
    };

    return setrlimit(RLIMIT_CORE, &rlim);
}
#endif

static
void usage(void)
{
    printf("Feeds service.\n");
    printf("Usage: feedsd [OPTION]...\n");
    printf("\n");
    printf("First run options:\n");
    printf("  -d, --daemon              Run as daemon.\n");
    printf("  -c, --config=CONFIG_FILE  Set config file path.\n");
    printf("      --data-dir=PATH       Data location, override the option in config.\n");
    printf("\n");
    printf("Debugging options:\n");
    printf("      --debug               Wait for debugger attach after start.\n");
    printf("\n");
    printf("  -v, --version             Print version.\n");
    printf("\n");
}

#define CONFIG_NAME "feedsd.conf"
static const char *default_cfg_files[] = {
    "./" CONFIG_NAME,
    "../etc/feedsd/" CONFIG_NAME,
    "/usr/local/etc/feedsd/" CONFIG_NAME,
    "/etc/feedsd/" CONFIG_NAME,
    NULL
};

static
void shutdown_proc(int signum)
{
    (void)signum;

    stop = true;
}

#if !defined(_WIN32) && !defined(_WIN64)
static
void print_backtrace(int sig) {
    std::cerr << "Error: signal " << sig << std::endl;

    std::string backtrace = trinity::Platform::GetBacktrace();
    std::cerr << backtrace << std::endl;

    exit(sig);
}
#endif

static
int daemonize()
{
#if !defined(_WIN32) && !defined(_WIN64)
    pid_t pid;
    struct sigaction sa;

    /*
     * Clear file creation mask.
     */
    umask(0);

    /*
     * Become a session leader to lose controlling TTY.
     */
    if ((pid = fork()) < 0)
        return -1;
    else if (pid != 0) /* parent */
        exit(0);
    setsid();

    /*
     * Ensure future opens won’t allocate controlling TTYs.
     */
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
        return -1;
    if ((pid = fork()) < 0)
        return -1;
    else if (pid != 0) /* parent */
        exit(0);

    /*
     * Change the current working directory to the root so
     * we won’t prevent file systems from being unmounted.
     */
    if (chdir("/") < 0)
        return -1;

    /* Attach file descriptors 0, 1, and 2 to /dev/null. */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDWR);
    dup(0);
    dup(0);
#endif

    return 0;
}

static
void transport_deinit()
{
    trinity::CommandHandler::GetInstance()->cleanup();
    trinity::MassDataManager::GetInstance()->cleanup();
    carrier_instance.reset();
    carrier = NULL;
}

static
int transport_init(FeedsConfig *cfg)
{
    int rc;
    CarrierCallbacks callbacks;

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.idle = idle_callback;
    callbacks.connection_status = on_connection_status;
    callbacks.friend_connection = friend_connection_callback;
    callbacks.friend_request = friend_request_callback;
    callbacks.friend_message = on_receiving_message;

    DIDBackend_InitializeDefault(create_id_tsx, resolver, cfg->didcache_dir);

    auto creater = [&]() -> Carrier* {
        vlogD(TAG_MAIN "Create carrier instance.");
        auto ptr = carrier_new(&cfg->carrier_opts, &callbacks, NULL);
        return ptr;
    };
    auto deleter = [=](Carrier* ptr) -> void {
        vlogD(TAG_MAIN "Destroy carrier instance.");
        if(ptr != nullptr) {
            carrier_kill(ptr);
        }
    };
    carrier_instance = std::shared_ptr<Carrier>(creater(), deleter);
    carrier = carrier_instance.get();
    if (!carrier) {
        vlogE(TAG_MAIN "Creating carrier instance failed");
        goto failure;
    }

    rc = trinity::CommandHandler::GetInstance()->config(cfg->data_dir, carrier_instance);
    if(rc < 0) {
        vlogE(TAG_MAIN "Config command handler failed");
        goto failure;
    }
    rc = trinity::MassDataManager::GetInstance()->config(cfg->data_dir, carrier_instance);
    if(rc < 0) {
        vlogE(TAG_MAIN "Carrier session init failed");
        goto failure;
    }

    vlogI(TAG_MAIN "Transport module initialized.");

    return 0;

failure:
    transport_deinit();
    return -1;
}

int main(int argc, char *argv[])
{
    char buf[CARRIER_MAX_ADDRESS_LEN + 1];
    const char *cfg_file = NULL;
    const char *data_dir = NULL;
    int wait_for_attach = 0;
    FeedsConfig cfg;
    int daemon = 0;
    int rc;

    int opt;
    int idx;
    struct option options[] = {
        { "daemon",      no_argument,        NULL, 'd' },
        { "config",      required_argument,  NULL, 'c' },
        { "data-dir",    required_argument,  NULL,  6  },
        { "debug",       no_argument,        NULL,  5  },
        { "help",        no_argument,        NULL, 'h' },
        { "version",     no_argument,        NULL, 'v' },
        { NULL,          0,                  NULL, 0 }
    };

#ifdef HAVE_SYS_RESOURCE_H
    sys_coredump_set(true);
#endif

    while ((opt = getopt_long(argc, argv, "dc:hv?", options, &idx)) != -1) {
        switch (opt) {
        case 'd':
            daemon = 1;
            break;

        case 'c':
            cfg_file = optarg;
            break;



        case 1:
        case 2:
        case 3:
        case 4:
            break;

        case 5:
            wait_for_attach = 1;
            break;

        case 6:
            data_dir = optarg;
            break;

        case 'v':
            printf("%s", FEEDSD_VER);
            exit(0);

        case 'h':
        case '?':
        default:
            usage();
            exit(-1);
        }
    }

#if !defined(_WIN32) && !defined(_WIN64)
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
#endif

    if (wait_for_attach) {
        printf("Wait for debugger attaching, process id is: %d.\n", getpid());
        printf("After debugger attached, press any key to continue......");
        getchar();
    }

    cfg_file = get_cfg_file(cfg_file, default_cfg_files);
    if (!cfg_file) {
        vlogE(TAG_MAIN "Missing config file.");
        usage();
        return -1;
    }

    memset(&cfg, 0, sizeof(cfg));
    if (!load_cfg(cfg_file, &cfg, data_dir)) {
        vlogE(TAG_MAIN "Loading configure failed!");
        return -1;
    }

    rc = transport_init(&cfg);
    if (rc < 0) {
        free_cfg(&cfg);
        return -1;
    }

    rc = msgq_init();
    if (rc < 0) {
        free_cfg(&cfg);
        transport_deinit();
        return -1;
    }

    rc = trinity::DataBase::GetInstance()->config(cfg.db_fpath);
    if (rc < 0) {
        free_cfg(&cfg);
        msgq_deinit();
        transport_deinit();
        return -1;
    }

    rc = did_init(&cfg);
    if (rc < 0) {
        free_cfg(&cfg);
        trinity::DataBase::GetInstance()->cleanup();
        msgq_deinit();
        transport_deinit();
        return -1;
    }

    rc = auth_init();
    if (rc < 0) {
        free_cfg(&cfg);
        did_deinit();
        trinity::DataBase::GetInstance()->cleanup();
        msgq_deinit();
        transport_deinit();
        return -1;
    }

    rc = feeds_init(&cfg);
    if (rc < 0) {
        free_cfg(&cfg);
        auth_deinit();
        did_deinit();
        trinity::DataBase::GetInstance()->cleanup();
        msgq_deinit();
        transport_deinit();
        return -1;
    }

    signal(SIGINT, shutdown_proc);
    signal(SIGTERM, shutdown_proc);

#if !defined(_WIN32) && !defined(_WIN64)
    signal(SIGSEGV, print_backtrace);
    signal(SIGABRT, print_backtrace);
#endif

    vlogI(TAG_MAIN "Feedsd version: %s", FEEDSD_VER);
    vlogI(TAG_MAIN "Carrier node identities:");
    vlogI(TAG_MAIN "  Node ID  : %s", carrier_get_nodeid(carrier, buf, sizeof(buf)));
    vlogI(TAG_MAIN "  User ID  : %s", carrier_get_userid(carrier, buf, sizeof(buf)));
    vlogI(TAG_MAIN "  Address  : %s", carrier_get_address(carrier, buf, sizeof(buf)));
    if (feeds_owner_info.did && feeds_owner_info.did[0])
        vlogI(TAG_MAIN "  Owner DID: %s", feeds_owner_info.did);
    if (feeds_did_str[0])
        vlogI(TAG_MAIN "  Feeds DID: %s", feeds_did_str);

    if (!did_is_ready())
        vlogI(TAG_MAIN "Visit http://YOUR-IP-ADDRESS:%s using your browser to start binding process."
               "Verification code:[%s]", cfg.http_port, did_get_nonce());
    else
        vlogI(TAG_MAIN "Visiting http://YOUR-IP-ADDRESS:%s with your browser to retrieve the QRcode "
               "of feeds URL", cfg.http_port);
    free_cfg(&cfg);

    if (daemon && daemonize() < 0) {
        fprintf(stderr, "Demonize failure!\n");
        feeds_deinit();
        auth_deinit();
        did_deinit();
        trinity::DataBase::GetInstance()->cleanup();
        msgq_deinit();
        transport_deinit();
        return -1;
    }

    rc = carrier_run(carrier, 10);

    feeds_deinit();
    auth_deinit();
    did_deinit();
    trinity::DataBase::GetInstance()->cleanup();
    msgq_deinit();
    transport_deinit();

    return rc;
}
