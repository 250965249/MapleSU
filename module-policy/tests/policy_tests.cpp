// Runs without live policy writes. Supply a saved policy image and writable temp directory.
#include <string>
static std::string shared_state_path;
#define MAPLE_SHARED_CONTEXT_STATE shared_state_path.c_str()
#define main policy_cli_main
#include "../src/main.cpp"
#undef main
int boot_sdk_control(int, char**) { throw std::runtime_error("BOOT_SDK_NOT_A_POLICY_TEST"); }
#include <sepol/policydb/services.h>
#include <sepol/policydb/sidtab.h>

namespace {
int passed = 0;
void test(const char *name, const std::function<void()> &body) {
    body();
    ++passed;
    printf("{\"test\":%s,\"status\":\"passed\"}\n", quote(name).c_str());
}
void expect(bool ok, const char *message) { if (!ok) throw Failure(message); }
void rejects(const std::function<void()> &body, std::string_view expected) {
    try { body(); } catch (const Failure &e) {
        expect(std::string_view(e.what()).find(expected) != std::string::npos, e.what());
        return;
    }
    throw Failure("expected failure was accepted");
}
uint32_t file_access(sepol_impl &db, const char *source, const char *target) {
    sidtab_t table;
    expect(sepol_sidtab_init(&table) == 0, "SID table initialization failed");
    sepol_set_policydb(db.db);
    sepol_set_sidtab(&table);
    sepol_security_id_t source_sid = 0, target_sid = 0;
    sepol_security_class_t cls = 0;
    sepol_av_decision decision{};
    int rc = sepol_context_to_sid(source, strlen(source), &source_sid);
    if (!rc) rc = sepol_context_to_sid(target, strlen(target), &target_sid);
    if (!rc) rc = sepol_string_to_security_class("file", &cls);
    if (!rc) rc = sepol_compute_av(source_sid, target_sid, cls, UINT32_MAX, &decision);
    sepol_sidtab_destroy(&table);
    sepol_set_sidtab(nullptr);
    sepol_set_policydb(nullptr);
    expect(rc == 0, "real SELinux access evaluation failed");
    return decision.allowed;
}
uint32_t file_permission(sepol_impl &db, const char *name) {
    auto cls = static_cast<class_datum_t *>(hashtab_search(db.db->p_classes.table, "file"));
    auto permission = static_cast<perm_datum_t *>(hashtab_search(cls->permissions.table, name));
    if (!permission && cls->comdatum)
        permission = static_cast<perm_datum_t *>(hashtab_search(cls->comdatum->permissions.table, name));
    expect(permission != nullptr, "file permission missing");
    return 1U << (permission->s.value - 1);
}
} // namespace

int main(int argc, char **argv) {
    try {
        if (argc != 3) throw Failure("usage: maplesu-policy-tests SAVED_POLICY TEMP_DIR");
        auto fixture = read_file(argv[1]);
        shared_state_path = std::string(argv[2]) + "/shared-context";
        test("shared data adapter matches the active boot and exact revision only", [&] {
            std::string directory = std::string(argv[2]) + "/shared-module";
            expect(mkdir(directory.c_str(), 0700) == 0 || errno == EEXIST, "fixture mkdir failed");
            std::string policy = directory + "/sepolicy.rule", library = directory + "/shim.so";
            const std::string source = "# original module rules\ntype lsposed_file file_type\n"
                "typeattribute lsposed_file mlstrustedobject\nallow domain lsposed_file dir *\n"
                "allow domain lsposed_file file *\nallow system_server apk_data_file file execute\n";
            auto put = [&](const std::string &name, const std::string &text) {
                std::ofstream out(name); out << text; out.close(); expect(!out.fail(), "fixture write failed");
            };
            put(policy, source); put(library, "fixture");
            unlink(shared_state_path.c_str());
            auto plain = read_rules({policy});
            struct stat st; expect(stat(directory.c_str(), &st) == 0, "fixture stat failed");
            std::ifstream epoch("/proc/sys/kernel/random/boot_id"); std::string boot; epoch >> boot;
            auto record = [&](const std::string &id, unsigned long long inode) {
                put(shared_state_path, id + " " + std::to_string(st.st_dev) + " " + std::to_string(inode) + " " + library + "\n");
            };
            record("old-boot", st.st_ino);
            expect(read_rules({policy}).size() == plain.size(), "old boot activated adapter");
            record(boot, st.st_ino + 1);
            expect(read_rules({policy}).size() == plain.size(), "other revision activated adapter");
            record(boot, st.st_ino);
            auto adapted = read_rules({policy});
            expect(adapted.size() + 4 == plain.size(), "expected shared data rules not replaced");
            for (const auto &rule : adapted) expect(rule.text.find("lsposed_file") == std::string::npos, "custom label remained");
            auto db = decode(fixture);
            size_t count = 0; expect(apply_all(*db, adapted, count, false), "adapted module rules failed");
            std::vector<Rule> unrelated{{"fixture", "allow system_server apk_data_file file execute", 1}};
            auto control = decode(fixture); count = 0;
            expect(apply_all(*control, unrelated, count, false), "control rule failed");
            expect(encode(*db) == encode(*control), "shared adapter widened stock policy");
            put(policy, source + "allow zygote lsposed_file file execute\n");
            rejects([&] { read_rules({policy}); }, "unsupported LSPosed");
            unlink(shared_state_path.c_str());
            expect(read_rules({policy}).size() == plain.size() + 1, "Normal contract changed without marker");
            unlink(policy.c_str()); unlink(library.c_str()); rmdir(directory.c_str());
        });

        test("policy decode/encode/readback", [&] {
            auto db = decode(fixture);
            auto image = encode(*db);
            auto copy = decode(image);
            expect(copy->db->policyvers == db->db->policyvers, "policy version changed");
            expect(copy->db->p_types.nprim == db->db->p_types.nprim, "type count changed");
        });
        test("Android live export retains netlink boundaries", [&] {
            auto db = decode(fixture);
            auto cls = static_cast<class_datum_t *>(hashtab_search(db->db->p_classes.table, "netlink_route_socket"));
            expect(cls != nullptr, "netlink class missing from Android fixture");
            expect(hashtab_search(cls->permissions.table, "nlmsg_readpriv"), "GETLINK permission missing");
            expect(hashtab_search(cls->permissions.table, "nlmsg_getneigh"), "GETNEIGH permission missing");
            db->db->android_extra = 0;
            restore_android_netlink(*db, 29);
            expect(db->db->android_extra == 0, "pre-Android 11 boundary changed");
            restore_android_netlink(*db, 30);
            expect(db->db->android_extra == static_cast<uint32_t>(POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE), "Android 11 GETLINK bit missing");
            restore_android_netlink(*db, 33);
            auto bits = static_cast<uint32_t>(POLICYDB_CONFIG_ANDROID_EXTRA_MASK);
            expect(db->db->android_extra == bits, "Android 13 netlink bits missing");
            auto image = encode(*db);
            auto copy = decode(image);
            expect(copy->db->android_extra == bits, "netlink bits lost before kernel load");
            auto before = encode(*copy);
            restore_android_netlink(*copy, 36);
            expect(encode(*copy) == before, "netlink restoration is not idempotent");
        });
        test("policy configuration and security bitmaps survive round trips", [&] {
            for (auto unknown : {DENY_UNKNOWN, REJECT_UNKNOWN, ALLOW_UNKNOWN}) {
                for (auto bits : {uint32_t{0}, static_cast<uint32_t>(POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE),
                                  static_cast<uint32_t>(POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH),
                                  static_cast<uint32_t>(POLICYDB_CONFIG_ANDROID_EXTRA_MASK)}) {
                    auto db = decode(fixture);
                    db->db->handle_unknown = unknown;
                    db->db->android_extra = bits;
                    for (int round = 0; round < 3; ++round) {
                        auto image = encode(*db);
                        auto copy = decode(image);
                        expect(copy->db->policyvers == db->db->policyvers, "policy version changed");
                        expect(copy->db->mls == db->db->mls, "MLS configuration changed");
                        expect(copy->db->handle_unknown == db->db->handle_unknown, "unknown permission handling changed");
                        expect(copy->db->android_extra == bits, "Android configuration changed");
                        expect(ebitmap_cmp(&copy->db->policycaps, &db->db->policycaps), "policy capabilities changed");
                        expect(ebitmap_cmp(&copy->db->permissive_map, &db->db->permissive_map), "permissive domains changed");
                        db = std::move(copy);
                    }
                }
            }
        });
        test("netlink repair requires matching policy permissions", [&] {
            auto db = decode(fixture);
            auto cls = static_cast<class_datum_t *>(hashtab_search(db->db->p_classes.table, "netlink_route_socket"));
            expect(cls != nullptr, "netlink class missing from Android fixture");
            auto permissions = cls->permissions.table;
            cls->permissions.table = nullptr;
            db->db->android_extra = 0;
            restore_android_netlink(*db, 36);
            cls->permissions.table = permissions;
            expect(db->db->android_extra == 0, "unsupported Android netlink configuration added");
        });
        test("strict parser sets/colon/self", [&] {
            Parser p("allow { a b } self:tcp_socket { read write }; # comment");
            expect(p.one() == "allow", "action mismatch");
            expect(p.group() == Strings({"a", "b"}), "set mismatch");
            expect(p.group() == Strings({"self"}), "self mismatch");
            expect(p.group(true) == Strings({"tcp_socket"}), "class mismatch");
            expect(p.group() == Strings({"read", "write"}), "permissions mismatch"); p.end();
        });
        test("strict parser rejects malformed sets", [&] {
            rejects([] { Parser p("{}"); p.group(); }, "empty set");
            rejects([] { Parser p("{ a"); p.group(); }, "unclosed set");
            rejects([] { Parser p("{ a * }"); p.group(); }, "wildcard");
            rejects([] { Parser p("\"unfinished"); }, "unterminated");
            rejects([] { Parser p("a b"); p.one(); p.end(); }, "trailing");
        });
        test("unknown type fails with object name", [&] {
            auto db = decode(fixture);
            rejects([&] { apply_rule(*db, {"fixture", "allow MAPLESU_MISSING_TYPE self file read", 1}); }, "MAPLESU_MISSING_TYPE");
        });
        test("invalid operation rejected", [&] {
            auto db = decode(fixture);
            rejects([&] { apply_rule(*db, {"fixture", "bogus a", 1}); }, "unsupported operation");
        });
        test("module domain state persists and can return to enforcing", [&] {
            auto db = decode(fixture);
            std::vector<Rule> rules{{"fixture", "type maplesu_test_permissive", 1},
                {"fixture", "permissive maplesu_test_permissive", 2}};
            size_t operations = 0;
            expect(apply_all(*db, rules, operations, false), "module domain state rejected");
            auto image = encode(*db);
            auto copy = decode(image);
            verify_rules(*copy, rules);
            apply_rule(*copy, {"fixture", "enforce maplesu_test_permissive", 3});
            expect(image != encode(*copy), "domain state did not change");
        });
        test("type/attribute declarations persist and replay", [&] {
            auto db = decode(fixture);
            std::vector<Rule> rules{{"fixture", "attribute maplesu_test_attribute", 1}, {"fixture", "type maplesu_test_type maplesu_test_attribute", 2}};
            size_t operations = 0;
            expect(apply_all(*db, rules, operations, false), "declaration rejected");
            expect(operations == 3, "unexpected operation count");
            auto image = encode(*db);
            auto copy = decode(image);
            verify_rules(*copy, rules);
            rejects([&] { apply_rule(*copy, {"fixture", "attribute maplesu_test_type", 3}); }, "different flavor");
        });
        test("deny removes inherited permissions without changing other pairs", [&] {
            auto db = decode(fixture);
            const Strings setup{
                "attribute maplesu_deny_sources",
                "typeattribute { untrusted_app zygote } maplesu_deny_sources",
                "attribute maplesu_deny_targets",
                "type maplesu_deny_one { file_type mlstrustedobject maplesu_deny_targets }",
                "type maplesu_deny_two { file_type mlstrustedobject maplesu_deny_targets }",
                "allow maplesu_deny_sources maplesu_deny_targets file { read write }",
                "allow untrusted_app maplesu_deny_one file getattr",
            };
            for (const auto &text : setup) apply_rule(*db, {"fixture", text, 1});
            const char *sources[]{"u:r:untrusted_app:s0", "u:r:zygote:s0"};
            const char *targets[]{"u:object_r:maplesu_deny_one:s0", "u:object_r:maplesu_deny_two:s0"};
            uint32_t original[2][2];
            auto read = file_permission(*db, "read");
            auto write = file_permission(*db, "write");
            for (int s = 0; s < 2; ++s) for (int t = 0; t < 2; ++t) {
                original[s][t] = file_access(*db, sources[s], targets[t]);
                expect((original[s][t] & (read | write)) == (read | write), "inherited grant fixture missing");
            }
            Rule rule{"fixture", "deny untrusted_app maplesu_deny_one file read", 1};
            apply_rule(*db, rule);
            auto image = encode(*db);
            auto copy = decode(image);
            for (int s = 0; s < 2; ++s) for (int t = 0; t < 2; ++t) {
                uint32_t expected = original[s][t] & ((s == 0 && t == 0) ? ~read : UINT32_MAX);
                expect(file_access(*copy, sources[s], targets[t]) == expected,
                    "effective deny left an inherited grant or changed an unrelated permission");
            }
            auto before_replay = encode(*copy);
            apply_rule(*copy, rule);
            expect(encode(*copy) == before_replay, "effective deny replay changed policy");
            apply_rule(*copy, {"fixture", "deny maplesu_deny_sources maplesu_deny_targets file write", 2});
            for (int s = 0; s < 2; ++s) for (int t = 0; t < 2; ++t)
                expect(!(file_access(*copy, sources[s], targets[t]) & write), "attribute deny left a grant");
        });
        test("deny covers overlapping attributes and wildcard permissions", [&] {
            auto db = decode(fixture);
            const Strings setup{
                "attribute maplesu_overlap_sources",
                "typeattribute { untrusted_app zygote } maplesu_overlap_sources",
                "attribute maplesu_overlap_one",
                "typeattribute untrusted_app maplesu_overlap_one",
                "type maplesu_overlap_file { file_type mlstrustedobject }",
                "allow maplesu_overlap_sources maplesu_overlap_file file { read write }",
                "allow maplesu_overlap_one maplesu_overlap_file file read",
                "allow untrusted_app maplesu_overlap_file file { read getattr }",
            };
            for (const auto &text : setup) apply_rule(*db, {"fixture", text, 1});
            auto read = file_permission(*db, "read");
            auto source = "u:r:untrusted_app:s0";
            auto other = "u:r:zygote:s0";
            auto target = "u:object_r:maplesu_overlap_file:s0";
            auto original = file_access(*db, source, target);
            auto preserved = file_access(*db, other, target);
            expect(original & read, "overlap fixture grant missing");
            apply_rule(*db, {"fixture", "deny untrusted_app maplesu_overlap_file file read", 2});
            expect(file_access(*db, source, target) == (original & ~read), "overlapping allow survived deny");
            expect(file_access(*db, other, target) == preserved, "overlap deny changed another source");
            apply_rule(*db, {"fixture", "deny * maplesu_overlap_file file *", 3});
            auto image = encode(*db);
            auto copy = decode(image);
            expect(file_access(*copy, source, target) == 0, "wildcard deny left source permissions");
            expect(file_access(*copy, other, target) == 0, "wildcard deny left inherited permissions");
        });
        test("deny rejects conditional overlap instead of granting it unconditionally", [&] {
            auto db = decode(fixture);
            apply_rule(*db, {"fixture", "type maplesu_cond_file { file_type mlstrustedobject }", 1});
            auto types = db->db->p_types.table;
            auto source = static_cast<type_datum_t *>(hashtab_search(types, "domain"))->s.value;
            auto target = static_cast<type_datum_t *>(hashtab_search(types, "maplesu_cond_file"))->s.value;
            auto cls = static_cast<class_datum_t *>(hashtab_search(db->db->p_classes.table, "file"))->s.value;
            auto read = file_permission(*db, "read");
            if (!db->db->te_cond_avtab.nslot)
                expect(avtab_alloc(&db->db->te_cond_avtab, 1) == 0, "conditional table allocation failed");
            avtab_key_t key{static_cast<uint16_t>(source), static_cast<uint16_t>(target),
                static_cast<uint16_t>(cls), AVTAB_ALLOWED};
            avtab_datum_t value{read, nullptr};
            auto node = avtab_insert_nonunique(&db->db->te_cond_avtab, &key, &value);
            expect(node != nullptr, "conditional fixture allocation failed");
            for (auto state : {AVTAB_ALLOWED, AVTAB_ALLOWED | AVTAB_ENABLED}) {
                node->key.specified = state;
                auto before = file_access(*db, "u:r:untrusted_app:s0", "u:object_r:maplesu_cond_file:s0");
                rejects([&] { apply_rule(*db, {"fixture", "deny untrusted_app maplesu_cond_file file read", 2}); },
                    "conditional grant");
                expect(node->datum.data == read, "conditional grant was rewritten");
                expect(file_access(*db, "u:r:untrusted_app:s0", "u:object_r:maplesu_cond_file:s0") == before,
                    "conditional fixture became an unconditional grant");
            }
        });
        test("candidate semantic verification detects absent declarations", [&] {
            auto db = decode(fixture);
            rejects([&] { verify_rules(*db, {{"fixture", "type maplesu_test_absent", 1}}); }, "expected rules missing");
        });
        test("write error reports errno and bytes", [&] {
            rejects([&] { write_once(-1, {'a'}); }, "written_bytes=-1");
        });
        test("short write fails without appending", [&] {
            int pipefd[2];
            if (pipe2(pipefd, O_NONBLOCK | O_CLOEXEC)) system_error("pipe2");
            Fd reader(pipefd[0]), writer(pipefd[1]);
            std::vector<char> bytes(4 * 1024 * 1024, 'x');
            rejects([&] { write_once(writer.value, bytes); }, "short policy write");
        });
        test("save creates complete regular file", [&] {
            std::string path = std::string(argv[2]) + "/maplesu-policy-test-XXXXXX";
            std::vector<char> name(path.begin(), path.end()); name.push_back(0);
            Fd temp(mkstemp(name.data()));
            if (temp.value < 0) system_error("mkstemp test");
            try { save(name.data(), fixture); expect(read_file(name.data()) == fixture, "saved bytes differ"); }
            catch (...) { unlink(name.data()); throw; }
            unlink(name.data());
        });
        printf("{\"tests_passed\":%d,\"live_policy_writes\":0}\n", passed);
        return 0;
    } catch (const std::exception &e) {
        printf("{\"tests_passed\":%d,\"status\":\"failed\",\"message\":%s}\n", passed, quote(e.what()).c_str());
        return 1;
    }
}
