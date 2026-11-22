#include "maplesu_module_control.h"
#include "module_err_def.h"
#include <tuple>
#include "maplesu_sdk/maplesu_installer.h"
#include "maplesu_sdk/maplesu_module.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
namespace fs = std::filesystem;
std::string fixture;
constexpr const char* id = "touch_boost_oplus_1021_000000000";
const char* key = "0123456789abcdef0123456789abcdef";
extern "C" void maplesu_system_directory(std::string* out) { *out = fixture; }
extern "C" void maplesu_installed_helper_path(std::string* out) { *out = fixture + "/init"; }
namespace default_modules::module_root { KModErr set_current_root(bool) { return KModErr::OK; } }
namespace maplesu::sdk {
KModErr get_root(const char*) { return KModErr::OK; }
MapleSUEnvState get_maplesu::sdkironment_state(const char*) {
 return fs::exists(fixture+"/fault") ? MapleSUEnvState::Fault : MapleSUEnvState::Running;
}
KModErr unsafe_get_all_modules(std::vector<module_record>& out) {
 if (!fs::exists(fixture+"/modules/"+id)) return KModErr::OK;
 module_record row{};strcpy(row.desc.id32,id);int state=0;std::ifstream(fixture+"/runtime")>>state;
 row.state=static_cast<ModuleRunState>(state);out.push_back(row);return KModErr::OK;
}
}
std::string read(const fs::path& path) { std::ifstream s(path);return {std::istreambuf_iterator<char>(s),{}}; }
void write(const fs::path& path,const std::string& text) {std::ofstream(path)<<text;}
extern "C" KModErr maplesu_lock_module_root(bool);
extern "C" [[noreturn]] void maplesu_module_worker_exit(int);
int main(int argc,char** argv) {
 assert(argc==2);char temp[]="/tmp/maplesu-control-XXXXXX";fixture=mkdtemp(temp);assert(!fixture.empty());
 fs::create_directories(fixture+"/modules/"+id);fs::copy_file(argv[1],fixture+"/init");
 fs::path state=fixture+"/modules/"+id+"/.maplesu-state";
 bool supported=false;maplesu::ModuleControlState out;
 assert(maplesu::module_control_capability(key,supported)==0 && supported);
 assert(maplesu::get_module_control(key,id,out)==0 && out.enabled==1 && out.needsReboot==1);
 write(fixture+"/runtime","1");
 assert(maplesu::set_module_enabled(key,id,false,out)==0 && !out.enabled && out.runtimeState==1 && out.needsReboot);
 const auto committed=read(state);assert(committed.size()==38 && committed[0]=='0');
 assert(maplesu::set_module_enabled(key,id,false,out)==0 && read(state)==committed);
 assert(maplesu::get_module_control(key,id,out)==0 && !out.enabled && out.runtimeState==1);
 puts("PASS persistent desired state / running disabled requires reboot / idempotency");
 write(fixture+"/runtime","0");std::string oldboot=committed;oldboot.replace(1,36,"00000000-0000-0000-0000-000000000000");write(state,oldboot);
 assert(maplesu::get_module_control(key,id,out)==0 && !out.enabled && !out.needsReboot);
 assert(maplesu::set_module_enabled(key,id,true,out)==0 && out.enabled && out.runtimeState==0 && out.needsReboot);
 puts("PASS later boot disabled / re-enable pending existing boot lifecycle");
 for (auto bad : {"", ".", "..", "../aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/"})
  assert(maplesu::set_module_enabled(key,bad,false,out)==maplesu::MODULE_CONTROL_INVALID_ID);
 assert(maplesu::get_module_control(key,"short",out)==maplesu::MODULE_CONTROL_NOT_FOUND);
 assert(maplesu::get_module_control(key,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",out)==maplesu::MODULE_CONTROL_NOT_FOUND);
 write(fixture+"/runtime","3");assert(maplesu::set_module_enabled(key,id,false,out)==maplesu::MODULE_CONTROL_NOT_FOUND);write(fixture+"/runtime","0");
 puts("PASS invalid / missing / removed-pending IDs");
 write(fixture+"/fault","");assert(maplesu::set_module_enabled(key,id,false,out)==maplesu::MODULE_CONTROL_ENVIRONMENT);fs::remove(fixture+"/fault");
 write(state,"0");assert(maplesu::get_module_control(key,id,out)==maplesu::MODULE_CONTROL_IO);write(state,committed);
 write(state.string()+".tmp","1");assert(maplesu::get_module_control(key,id,out)==0 && !out.enabled);
 assert(maplesu::set_module_enabled(key,id,true,out)==0 && read(state).size()==38);
 fs::remove(state);fs::create_symlink("/dev/null",state);assert(maplesu::get_module_control(key,id,out)==maplesu::MODULE_CONTROL_IO);fs::remove(state);
 puts("PASS safe mode / corrupt state / interrupted temp / symlink");
 std::vector<pid_t> children;
 for(int i=0;i<20;++i) {pid_t child=fork();assert(child>=0);if(!child){maplesu::ModuleControlState row;_exit(maplesu::set_module_enabled(key,id,(i&1)!=0,row)==0?0:1);}children.push_back(child);}
 for(auto child:children){int status=0;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);}
 assert(maplesu::get_module_control(key,id,out)==0);assert(read(state).size()==38);
 puts("PASS 20 concurrent persistent toggles");
 // The exec child shares the lock's open-file description. Its exit must not unlock the worker.
 int ready[2],resume[2];assert(pipe(ready)==0 && pipe(resume)==0);
 pid_t holder=fork();assert(holder>=0);
 if(!holder) {
  assert(maplesu_lock_module_root(true)==KModErr::OK);
  pid_t execChild=fork();assert(execChild>=0);if(!execChild)maplesu_module_worker_exit(127);
  int status;assert(waitpid(execChild,&status,0)==execChild);
  assert(::write(ready[1],"1",1)==1);char c;assert(::read(resume[0],&c,1)==1);
  fs::remove_all(fixture+"/modules/"+id);maplesu_module_worker_exit(0);
 }
 char c;assert(::read(ready[0],&c,1)==1);
 pid_t toggler=fork();assert(toggler>=0);
 if(!toggler){maplesu::ModuleControlState row;_exit(maplesu::set_module_enabled(key,id,false,row)==maplesu::MODULE_CONTROL_NOT_FOUND?0:2);}
 usleep(100000);int status=0;assert(waitpid(toggler,&status,WNOHANG)==0);
 assert(::write(resume[1],"1",1)==1);
 assert(waitpid(holder,&status,0)==holder && WEXITSTATUS(status)==0);
 assert(waitpid(toggler,&status,0)==toggler && WEXITSTATUS(status)==0);
 fs::create_directories(fixture+"/modules/"+id);
 close(ready[0]);close(ready[1]);close(resume[0]);close(resume[1]);
 puts("PASS overlapping uninstall / child exit retains worker lock / no resurrection");
 // Kernel closes the lock on an interrupted worker; the next request must make progress.
 assert(pipe(ready)==0);holder=fork();assert(holder>=0);
 if(!holder){assert(maplesu_lock_module_root(true)==KModErr::OK);assert(::write(ready[1],"1",1)==1);for(;;)pause();}
 assert(::read(ready[0],&c,1)==1);assert(kill(holder,SIGKILL)==0);assert(waitpid(holder,&status,0)==holder);
 assert(maplesu::set_module_enabled(key,id,false,out)==0);
 close(ready[0]);close(ready[1]);puts("PASS interrupted lock owner releases descriptor");
 // A worker interrupted before atomic rename leaves the last committed state intact.
 write(state.string()+".tmp","partially-written");const auto last=read(state);
 assert(maplesu::get_module_control(key,id,out)==0 && read(state)==last);
 fs::remove_all(fixture+"/modules/"+id);assert(maplesu::set_module_enabled(key,id,false,out)==maplesu::MODULE_CONTROL_NOT_FOUND);
 fs::create_directories(fixture+"/modules/"+id);assert(maplesu::get_module_control(key,id,out)==0 && out.enabled);
 puts("PASS interrupted commit / uninstall wins / reinstall defaults");
 {std::fstream helper(fixture+"/init",std::ios::in|std::ios::out|std::ios::binary);helper.seekp(0xa6d68);helper.put('\0');}
 assert(maplesu::module_control_capability(key,supported)==0 && !supported);
 assert(maplesu::set_module_enabled(key,id,false,out)==maplesu::MODULE_CONTROL_UNSUPPORTED);
 puts("PASS older installed helper reports capability=false");
 fs::remove_all(fixture);puts("PASS module callbacks and entry never called by control API");
}
