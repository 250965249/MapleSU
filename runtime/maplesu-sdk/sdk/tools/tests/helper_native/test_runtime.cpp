#include "../../../src/maplesu/module/runtime.h"
#include "../../../src/maplesu/module/state.h"
#include "../../../src/maplesu/module/operations.h"
#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <cstring>

namespace fs = std::filesystem;
using maplesu::module_state::List;
namespace runtime = maplesu::module_runtime;
static const char key[] = "1234567890abcdef1234567890abcdef1234567890abcdef";
static const char good[] = "0123456789abcdefghijklmnopqrstuv";
static const char fail[] = "1123456789abcdefghijklmnopqrstuv";
static const char missing[] = "2123456789abcdefghijklmnopqrstuv";
static const char bad[] = "3123456789abcdefghijklmnopqrstuv";
static int checks = 0;
static std::vector<maplesu::module::Record> records;
static std::string disabled;
void check(bool ok, const char* name) { ++checks; if (!ok) { std::cerr << "FAIL " << name << '\n'; std::exit(1); } }
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() { return key; }
extern "C" int __wrap_setxattr(const char*, const char*, const void*, size_t, int) { return 0; }
extern "C" int maplesu_skip_disabled(const char* directory) { return directory == disabled; }
namespace maplesu::module {
KModErr unsafe_get_all_modules(std::vector<Record>& out) { out = records; return KModErr::OK; }
}
static maplesu::module::Descriptor read_desc(const char* id) {
    const auto file = runtime::private_directory(key, id) + id;
    std::ifstream in(file, std::ios::binary);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(in), {}};
    maplesu::module::Descriptor desc;
    check(is_ok(maplesu::module::parse_metadata(bytes, desc)), "real metadata parser");
    return desc;
}
static bool listed(List list, const char* id) {
    std::vector<std::string> values;
    check(is_ok(maplesu::module_state::read(list, values)), "read real state");
    return std::find(values.begin(), values.end(), id) != values.end();
}
static int entries() {
    std::ifstream in("/tmp/helper-events"); std::string line; int count = 0;
    while (std::getline(in, line)) if (line.starts_with("entry:")) ++count;
    return count;
}
int main() {
    const auto kernel = std::string("/data/") + std::string(key, 16);
    fs::create_directories(kernel);
    for (const char* id : {good, fail, missing, bad}) {
        fs::create_directories(runtime::private_directory(key, id));
        fs::copy_file(std::string("/work/") + id + ".so", runtime::private_directory(key, id) + id,
                      fs::copy_options::overwrite_existing);
    }
    const auto desc = read_desc(good);
    const auto before = fs::current_path();
    const std::string before_path = getenv("PATH");
    auto result = runtime::execute(desc, key);
    std::cerr << "first loader=" << static_cast<int64_t>(result.loader) << " main=" << result.entry << '\n';
    check(is_ok(result.loader) && result.entry == 0, "real DSO success results");
    check(fs::current_path() == before && getenv("PATH") == before_path, "child cwd/PATH isolated");
    std::ifstream event_input("/tmp/helper-events");
    std::string events{std::istreambuf_iterator<char>(event_input), {}};
    check(events.find(std::string("entry:") + key + ":" + runtime::private_directory(key, good)) != std::string::npos,
          "real legacy ABI key/private directory");
    check(events.find("unload\n") != std::string::npos, "dlclose destructor ran before result");
    result = runtime::execute(read_desc(fail), key);
    check(is_ok(result.loader) && result.entry == 42, "loader/main failure separated");
    result = runtime::execute(read_desc(missing), key);
    check(result.loader == KModErr::ERR_MODULE_DLSYM, "missing entry symbol");
    auto bad_desc = desc; strcpy(bad_desc.id32, bad);
    result = runtime::execute(bad_desc, key);
    check(result.loader == KModErr::ERR_MODULE_DLOPEN, "bad ELF");
    setenv("FIXTURE_ACTION", "exit", 1);
    result = runtime::execute(desc, key);
    check(result.loader == KModErr::ERR_READ_CHILD_ERRCODE, "module _exit cannot become success");
    setenv("FIXTURE_ACTION", "signal", 1);
    result = runtime::execute(desc, key);
    check(result.loader == KModErr::ERR_READ_CHILD_ERRCODE, "module signal cannot become success");
    unsetenv("FIXTURE_ACTION");
    setenv("FIXTURE_ACTION", "partial", 1);
    result = runtime::execute(desc, key);
    check(result.loader == KModErr::ERR_READ_CHILD_ERRCODE, "short result pipe is failure");
    unsetenv("FIXTURE_ACTION");
    records.push_back({desc});
    check(is_ok(maplesu::module_state::add(List::PendingRunOnce, good)), "request run-once");
    const int start = entries();
    std::vector<runtime::Record> batch;
    for (int boot = 0; boot < 3; ++boot) {
        check(is_ok(runtime::run_batch(key, {5, 2, 0}, batch)), "batch succeeds");
        check(batch.size() == 1 && batch[0].result.skipped == (boot != 0), "run-once three boot outcomes");
    }
    check(entries() == start + 1, "run-once durable across three boots");
    check(listed(List::FinishedRunOnce, good) && !listed(List::PendingRunOnce, good), "run-once state shared");
    result = runtime::run_single(key, good, {5, 2, 0});
    check(result.skipped && entries() == start + 1, "single shares consumed state");
    check(is_ok(maplesu::module_state::remove(List::FinishedRunOnce, good)) &&
          is_ok(maplesu::module_state::add(List::PendingRunOnce, good)), "reinstall requests new run-once");
    result = runtime::run_single(key, good, {5, 2, 0});
    check(is_ok(result.loader) && result.entry == 0 && entries() == start + 2, "single executes after reinstall");
    result = runtime::run_single(key, fail, {5, 2, 0});
    check(is_ok(result.loader) && result.entry == 42 && listed(List::Abnormal, fail), "single main error state");
    disabled = runtime::private_directory(key, good);
    result = runtime::run_single(key, good, {5, 2, 0});
    check(result.skipped && static_cast<int64_t>(result.loader) == -20150, "disabled boundary skip");
    disabled.clear();
    records.push_back({read_desc(fail)});
    check(is_ok(runtime::run_batch(key, {5, 2, 0}, batch)), "batch continues after module error");
    check(batch.size() == 2 && is_ok(batch[1].result.loader) && batch[1].result.entry == 42,
          "batch retains main result independently of state writes");
    check(listed(List::Abnormal, fail) && !listed(List::Running, fail), "batch failure is abnormal only");
    result = runtime::run_single(key, good, {4, 0, 4});
    check(result.loader == KModErr::ERR_MODULE_REQUIRE_MIN_SDK, "version gate uses current source version");
    std::cout << "PASS helper module runtime " << checks << " assertions\n";
}
