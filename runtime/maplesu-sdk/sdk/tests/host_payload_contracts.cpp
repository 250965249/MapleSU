// Host contract tests for the embedded payload programs.
//
// The payload programs are AArch64 Android executables, so their behaviour is
// checked on the host at the level the programs themselves depend on: the CLI
// contracts (pure parsing/validation code compiled by the same source headers),
// the persistent-property codec, the installer feature-token discipline and the
// static HTTP contract of the web UI fallback server (the real CivetWeb server,
// started on loopback and queried by a real HTTP client).
//
// Build/run through tests/run_host_payload_contracts.py.
//
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "civetweb.h"
#include "payload_support.h"
#include "resetprop/src/cli_contract.h"    // resetprop CLI
#include "resetprop/src/persist_proto.h"   // persistent-properties codec
#include "resetprop/src/prop_line.h"       // -f file grammar
#include "su/src/cli_contract.h"           // su CLI
#include "webui_loader/src/contract.h"     // webui_loader launch contract
#include "webui_loader/src/webroot_server.h"

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool condition, const char* what) {
    ++g_checks;
    if (condition) return;
    ++g_failures;
    std::printf("FAIL %s\n", what);
}

void check_str(const std::string& value, const std::string& expected, const char* what) {
    ++g_checks;
    if (value == expected) return;
    ++g_failures;
    std::printf("FAIL %s (got '%s', want '%s')\n", what, value.c_str(),
                expected.c_str());
}

// ---------------------------------------------------------------------------
// feature token: the installer's in-place replacement contract
// ---------------------------------------------------------------------------
void test_feature_token_rewrite() {
    // 128-character placeholder padded with NULs to the 4096-byte token block.
    std::string image(6000, 'x');
    const std::string placeholder(128, 'a');
    image.replace(100, 4096, placeholder + std::string(4096 - 128, '\0'));

    const std::string token = placeholder + std::string(4096 - 128, '\0');
    const size_t hit = image.find(token);
    check(hit == 100, "feature token located in image");

    const std::string key = "0123456789abcdef";
    std::string padded(4096, '\0');
    std::memcpy(padded.data(), key.c_str(), key.size() + 1);
    image.replace(hit, 4096, padded);
    check_str(image.substr(100, key.size() + 1), key + std::string(1, '\0'),
              "feature token rewritten in place");
    check(image.size() == 6000, "feature rewrite keeps the image length");
}

// ---------------------------------------------------------------------------
// webui_loader launch contract
// ---------------------------------------------------------------------------
void test_webui_contract() {
    using maplesu::payload::webui::LaunchArgs;
    using maplesu::payload::webui::parse_launch_args;

    const char* good[] = {"webui_loader", "0123456789abcdef0123456789abcdef",
                          "34567", "4242", "1"};
    LaunchArgs args;
    std::string error;
    check(parse_launch_args(5, good, args, error), "webui argv accepted");
    check_str(args.mod_id32, "0123456789abcdef0123456789abcdef", "webui mod_id32");
    check(args.port == 34567, "webui port");
    check(args.caller_pid == 4242, "webui caller pid");
    check(args.log_flag == 1, "webui log flag");

    const char* too_few[] = {"webui_loader", "0123456789abcdef0123456789abcdef",
                             "34567", "4242"};
    check(!parse_launch_args(4, too_few, args, error), "webui rejects missing argv");

    const char* bad_mod[] = {"webui_loader", "not-hex", "34567", "4242", "0"};
    check(!parse_launch_args(5, bad_mod, args, error), "webui rejects bad mod_id32");

    const char* bad_port_low[] = {"webui_loader", "0123456789abcdef0123456789abcdef",
                                  "19999", "4242", "0"};
    check(!parse_launch_args(5, bad_port_low, args, error), "webui rejects port < 20000");
    const char* bad_port_high[] = {"webui_loader", "0123456789abcdef0123456789abcdef",
                                   "60001", "4242", "0"};
    check(!parse_launch_args(5, bad_port_high, args, error), "webui rejects port > 60000");

    const char* bad_flag[] = {"webui_loader", "0123456789abcdef0123456789abcdef",
                              "34567", "4242", "yes"};
    check(!parse_launch_args(5, bad_flag, args, error), "webui rejects bad log flag");

    const std::string key = "0123456789abcdef0123456789abcdef";
    check_str(maplesu::payload::webui::data_dir(key), "/data/0123456789abcdef0/",
              "webui data dir");
    check_str(maplesu::payload::webui::modules_dir(key),
              "/data/0123456789abcdef0/modules/", "webui modules dir");
    check_str(maplesu::payload::webui::module_private_dir(key, "abcdef"),
              "/data/0123456789abcdef0/modules/abcdef/", "webui module private dir");
    check_str(maplesu::payload::webui::module_elf_path(key, "abcdef"),
              "/data/0123456789abcdef0/modules/abcdef/abcdef", "webui module elf path");
    check_str(maplesu::payload::webui::module_webroot_dir(key, "abcdef"),
              "/data/0123456789abcdef0/modules/abcdef/webroot", "webui module webroot");
    check(maplesu::payload::webui::data_dir("short").empty(), "webui short key rejected");
}

// ---------------------------------------------------------------------------
// resetprop CLI + file grammar + persistent codec
// ---------------------------------------------------------------------------
void test_resetprop_contract() {
    using maplesu::payload::resetprop::ParseKind;
    using maplesu::payload::resetprop::parse_cli;
    using maplesu::payload::resetprop::usage_text;

    auto parse = [](std::vector<const char*> argv) {
        return parse_cli(static_cast<int>(argv.size()), argv.data());
    };

    {
        const auto result = parse({"resetprop"});
        check(result.kind == ParseKind::Run, "resetprop bare invocation runs");
        check(result.options.args.empty(), "resetprop bare has no args");
    }
    {
        const auto result = parse({"resetprop", "ro.build.type"});
        check(result.kind == ParseKind::Run, "resetprop get accepted");
        check_str(result.options.args.at(0), "ro.build.type", "resetprop get key");
    }
    {
        const auto result = parse({"resetprop", "ro.test", "value"});
        check(result.kind == ParseKind::Run, "resetprop set accepted");
        check(result.options.args.size() == 2, "resetprop set two positionals");
    }
    {
        const auto result = parse({"resetprop", "-h"});
        check(result.kind == ParseKind::Help, "resetprop -h is help");
    }
    {
        const auto result = parse({"resetprop", "--help"});
        check(result.kind == ParseKind::Help, "resetprop --help is help");
    }
    {
        const auto result = parse({"resetprop", "-n", "-p", "persist.x", "v"});
        check(result.options.skip_svc && result.options.persist,
              "resetprop -n -p switches");
    }
    {
        const auto result = parse({"resetprop", "-f", "/tmp/props"});
        check(result.options.has_file, "resetprop -f takes value");
        check_str(result.options.file, "/tmp/props", "resetprop -f value");
    }
    {
        const auto result = parse({"resetprop", "--file=/tmp/props"});
        check(result.options.has_file, "resetprop --file=VALUE accepted");
        check_str(result.options.file, "/tmp/props", "resetprop --file=VALUE value");
    }
    {
        const auto result = parse({"resetprop", "-d", "persist.x"});
        check(result.options.has_delete, "resetprop -d accepted");
        check_str(result.options.delete_key, "persist.x", "resetprop -d value");
    }
    {
        const auto result = parse({"resetprop", "-w", "ro.test"});
        check(result.kind == ParseKind::Run, "resetprop -w accepted");
        check(result.options.wait_mode, "resetprop -w mode");
    }
    {
        const auto result = parse({"resetprop", "-w"});
        check(result.kind == ParseKind::Error, "resetprop -w needs NAME");
    }
    {
        const auto result = parse({"resetprop", "-f", "a", "-d", "b"});
        check(result.kind == ParseKind::Error, "resetprop rejects multiple modes");
    }
    {
        const auto result = parse({"resetprop", "a", "b", "c"});
        check(result.kind == ParseKind::Error, "resetprop rejects three positionals");
    }
    {
        const auto result = parse({"resetprop", "-w", "a", "b", "c"});
        check(result.kind == ParseKind::Error, "resetprop wait rejects extra args");
    }
    {
        const auto result = parse({"resetprop", "--bogus"});
        check(result.kind == ParseKind::Error, "resetprop rejects unknown long option");
    }
    {
        const auto result = parse({"resetprop", "-Z", "ro.test"});
        check(result.options.context, "resetprop -Z accepted");
    }
    {
        const std::string text = usage_text("resetprop");
        check(text.find("resetprop - System Property Manipulation Tool") != std::string::npos,
              "resetprop usage title");
        check(text.find("Usage: resetprop [flags] [arguments...]") != std::string::npos,
              "resetprop usage line");
        check(text.find("-mm") == std::string::npos, "resetprop usage has no su text");
    }

    // -f file grammar: trim, comments, first '=' splits.
    using maplesu::payload::resetprop::parse_prop_line;
    check(!parse_prop_line("").valid, "prop line: empty skipped");
    check(!parse_prop_line("   ").valid, "prop line: blank skipped");
    check(!parse_prop_line("# comment").valid, "prop line: comment skipped");
    check(!parse_prop_line("no separator").valid, "prop line: no '=' skipped");
    {
        const auto line = parse_prop_line("  persist.foo = bar = baz  \n");
        check(line.valid, "prop line: valid");
        check_str(line.key, "persist.foo", "prop line: key trimmed");
        check_str(line.value, "bar = baz", "prop line: value keeps later '='");
    }

    // persistent-properties proto2 codec round trip.
    using maplesu::payload::resetprop::PersistentRecord;
    std::vector<PersistentRecord> records;
    for (const char* name : {"persist.z", "persist.a", "persist.m"}) {
        PersistentRecord record;
        record.has_name = true;
        record.has_value = true;
        record.name = name;
        record.value = std::string("value-") + name;
        records.push_back(record);
    }
    const std::string encoded =
        maplesu::payload::resetprop::encode_persistent_properties(records);
    std::vector<PersistentRecord> decoded;
    check(maplesu::payload::resetprop::decode_persistent_properties(encoded, decoded),
          "persist codec decodes its own encoding");
    check(decoded.size() == records.size(), "persist codec record count");
    check_str(decoded.at(0).name, "persist.a", "persist codec sorts by name");
    check_str(decoded.at(2).name, "persist.z", "persist codec keeps names");
    const std::string reencoded =
        maplesu::payload::resetprop::encode_persistent_properties(decoded);
    check_str(reencoded, encoded, "persist codec round trip is byte-stable");

    // Unknown fields are skipped, not treated as records.
    const std::string with_unknown = std::string("\x08\x2a", 2) + encoded;
    std::vector<PersistentRecord> tolerant;
    check(maplesu::payload::resetprop::decode_persistent_properties(with_unknown, tolerant),
          "persist codec tolerates unknown fields");
    check(tolerant.size() == records.size(), "persist codec unknown field ignored");
}

// ---------------------------------------------------------------------------
// su CLI contract
// ---------------------------------------------------------------------------
void test_su_contract() {
    using maplesu::payload::su::SuParseKind;
    using maplesu::payload::su::parse_su_args;

    auto run = [](std::vector<std::string> words) {
        std::vector<char*> argv;
        for (auto& word : words) argv.push_back(word.data());
        return parse_su_args(static_cast<int>(argv.size()), argv.data());
    };

    {
        const auto result = run({"su", "-h"});
        check(result.kind == SuParseKind::Help, "su -h is help");
    }
    {
        const auto result = run({"su", "--help"});
        check(result.kind == SuParseKind::Help, "su --help is help");
    }
    {
        const auto result = run({"su", "-v"});
        check(result.kind == SuParseKind::Version, "su -v is version");
    }
    {
        const auto result = run({"su", "-V"});
        check(result.kind == SuParseKind::VersionCode, "su -V is version code");
    }
    {
        const auto result = run({"su"});
        check(result.kind == SuParseKind::Run, "su bare accepted");
        check_str(result.request.shell, "/system/bin/sh", "su default shell");
        check(!result.request.login && !result.request.keepenv, "su default flags");
    }
    {
        const auto result = run({"su", "-l"});
        check(result.request.login, "su -l login");
    }
    {
        const auto result = run({"su", "-p"});
        check(result.request.keepenv, "su -p preserve environment");
    }
    {
        const auto result = run({"su", "-s", "/system/bin/bash"});
        check_str(result.request.shell, "/system/bin/bash", "su -s shell");
    }
    {
        const auto result = run({"su", "-mm"});
        check(result.request.mount_master, "su -mm rewritten to -M");
    }
    {
        const auto result = run({"su", "-M"});
        check(result.request.mount_master, "su -M mount master");
    }
    {
        const auto result = run({"su", "-cn"});
        check(result.kind == SuParseKind::Run, "su -cn legacy rewrite accepted");
        check_str(result.request.context, "", "su -cn consumes no value");
    }
    {
        const auto result = run({"su", "0", "id"});
        check(result.kind == SuParseKind::Run, "su user + argument accepted");
        check(result.first_positional == 1, "su user positional index");
    }
    {
        const auto result = run({"su", "-", "0"});
        check(result.request.login, "su free-standing '-' is login");
        check(result.first_positional == 2, "su '-' advances positional index");
    }
    {
        const auto result = run({"su", "--bogus"});
        check(result.failed, "su rejects unknown option");
    }
    {
        const auto result = run({"su", "-c", "id", "-u"});
        check(result.kind == SuParseKind::Run, "su -c accepted");
        // The reference client folds argv[optind-1..] (getopt leaves optind past
        // the option and its argument, so the option itself is not re-added).
        check_str(result.request.command, "id -u", "su -c folds the command tail");
    }
}

// ---------------------------------------------------------------------------
// static HTTP contract of the web UI fallback server
// ---------------------------------------------------------------------------
#if defined(_WIN32)
#include <winsock2.h>
#endif

void test_webroot_http_contract() {
    namespace fs = std::filesystem;
    using maplesu::payload::webui::ServerConfig;
    using maplesu::payload::webui::WebRootServer;

    const fs::path root = fs::temp_directory_path() / "maplesu-payload-webroot-test";
    std::error_code ignored;
    fs::remove_all(root, ignored);
    fs::create_directories(root, ignored);
    {
        std::FILE* index = std::fopen((root / "index.html").string().c_str(), "wb");
        check(index != nullptr, "http test: index file created");
        if (index != nullptr) {
            std::fputs("<html>maplesu-index</html>", index);
            std::fclose(index);
        }
        std::FILE* asset = std::fopen((root / "hello.txt").string().c_str(), "wb");
        check(asset != nullptr, "http test: static file created");
        if (asset != nullptr) {
            std::fputs("maplesu-static-body", asset);
            std::fclose(asset);
        }
    }

    std::printf("[http] files prepared\n");
    WebRootServer server;
    ServerConfig config;
    config.document_root = root.string();
    bool started = false;
    int port = 0;
    for (int candidate = 39100; candidate < 39140 && !started; ++candidate) {
        config.port = candidate;
        started = server.start(config);
        if (started) port = candidate;
    }
    std::printf("[http] started=%d port=%d\n", started ? 1 : 0, port);
    check(started, "http test: server bound a loopback port");
    if (!started) {
        fs::remove_all(root, ignored);
        return;
    }

    // Raw HTTP client over winsock: the assertion is on the wire bytes, so the
    // server is exercised exactly as a browser would exercise it.
    auto fetch = [port](const char* path) {
        std::string response;
        const std::string request = std::string("GET ") + path + " HTTP/1.0\r\n\r\n";
        SOCKET socket_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket_fd == INVALID_SOCKET) return response;
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_port = htons(static_cast<unsigned short>(port));
        address.sin_addr.s_addr = inet_addr("127.0.0.1");
        if (::connect(socket_fd, reinterpret_cast<sockaddr*>(&address),
                      sizeof(address)) == SOCKET_ERROR) {
            ::closesocket(socket_fd);
            return response;
        }
        ::send(socket_fd, request.data(), static_cast<int>(request.size()), 0);
        char buffer[1024];
        while (true) {
            const int received = ::recv(socket_fd, buffer, sizeof(buffer), 0);
            if (received <= 0) break;
            response.append(buffer, static_cast<size_t>(received));
        }
        ::closesocket(socket_fd);
        return response;
    };

    const std::string index = fetch("/");
    check(index.find(" 200 OK") != std::string::npos, "http GET / returns 200");
    check(index.find("maplesu-index") != std::string::npos,
          "http GET / serves webroot/index.html");

    const std::string static_file = fetch("/hello.txt");
    check(static_file.find(" 200 OK") != std::string::npos,
          "http GET /hello.txt returns 200");
    check(static_file.find("maplesu-static-body") != std::string::npos,
          "http GET serves a webroot file");

    const std::string missing = fetch("/does-not-exist");
    check(missing.find("404") != std::string::npos, "http GET missing path returns 404");

    server.stop();
    check(!server.running(), "http test: server stopped");
    fs::remove_all(root, ignored);
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
#if defined(_WIN32)
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
    std::printf("[section] feature token\n");
    test_feature_token_rewrite();
    std::printf("[section] webui_loader contract\n");
    test_webui_contract();
    std::printf("[section] resetprop contract\n");
    test_resetprop_contract();
    std::printf("[section] su contract\n");
    test_su_contract();
    std::printf("[section] webroot http contract\n");
    test_webroot_http_contract();
#if defined(_WIN32)
    WSACleanup();
#endif
    std::printf("%d check(s), %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
