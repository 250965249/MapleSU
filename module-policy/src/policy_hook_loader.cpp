// SPDX-License-Identifier: GPL-3.0-only
// An explicit temporary-session action. Read-only settings never load modules.
#include "kernel_payload_hook.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>

namespace {
struct File {
    int fd;
    explicit File(const char* path):fd(open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW)) {
        if (fd<0) throw std::runtime_error("MODULE_POLICY_HOOK_FILE:"+std::to_string(errno));
    }
    ~File() { close(fd); }
};
std::vector<uint8_t> contents(int fd,size_t limit) {
    std::vector<uint8_t> result;
    uint8_t block[4096];
    for (;;) {
        auto size=read(fd,block,sizeof block);
        if (size<0 && errno==EINTR) continue;
        if (size<0) throw std::runtime_error("MODULE_POLICY_HOOK_READ:"+std::to_string(errno));
        if (!size) return result;
        if (result.size()+size>limit) throw std::runtime_error("MODULE_POLICY_HOOK_SIZE");
        result.insert(result.end(),block,block+size);
    }
}
bool range(size_t offset,size_t bytes,size_t limit) { return offset<=limit && bytes<=limit-offset; }
std::string live_id() {
    File notes("/sys/kernel/notes");
    return maplesu::module_policy::kernel_build_id(contents(notes.fd,65536));
}
std::string module_id(const std::vector<uint8_t>& image) {
    if(image.size()<sizeof(Elf64_Ehdr)) throw std::runtime_error("MODULE_POLICY_HOOK_ELF");
    Elf64_Ehdr header;memcpy(&header,image.data(),sizeof header);
    if(memcmp(header.e_ident,ELFMAG,SELFMAG) || header.e_ident[EI_CLASS]!=ELFCLASS64 ||
       header.e_ident[EI_DATA]!=ELFDATA2LSB || header.e_type!=ET_REL || header.e_machine!=EM_AARCH64 ||
       header.e_shentsize!=sizeof(Elf64_Shdr) || !header.e_shnum || header.e_shstrndx>=header.e_shnum ||
       !range(header.e_shoff,size_t(header.e_shnum)*sizeof(Elf64_Shdr),image.size()))
        throw std::runtime_error("MODULE_POLICY_HOOK_ELF");
    auto section=[&](unsigned i) {
        Elf64_Shdr row;memcpy(&row,image.data()+header.e_shoff+i*sizeof row,sizeof row);
        if(!range(row.sh_offset,row.sh_size,image.size()) && row.sh_type!=SHT_NOBITS)
            throw std::runtime_error("MODULE_POLICY_HOOK_SECTION");
        return row;
    };
    auto strings=section(header.e_shstrndx);
    std::string identity;bool named=false,abi=false;
    for(unsigned i=0;i<header.e_shnum;++i) {
        auto row=section(i);
        if(row.sh_name>=strings.sh_size) throw std::runtime_error("MODULE_POLICY_HOOK_SECTION_NAME");
        const char* name=reinterpret_cast<const char*>(image.data()+strings.sh_offset+row.sh_name);
        if(!memchr(name,0,strings.sh_size-row.sh_name)) throw std::runtime_error("MODULE_POLICY_HOOK_SECTION_NAME");
        if(strcmp(name,".modinfo")) continue;
        for(size_t at=0;at<row.sh_size;) {
            const char* record=reinterpret_cast<const char*>(image.data()+row.sh_offset+at);
            auto end=static_cast<const char*>(memchr(record,0,row.sh_size-at));
            if(!end) throw std::runtime_error("MODULE_POLICY_HOOK_MODINFO");
            std::string_view text(record,end-record);
            named|=text=="name=maplesu_policy_hook";
            abi|=text=="maplesu_policy_hook_abi=2";
            constexpr std::string_view prefix="maplesu_image_build_id=";
            if(text.starts_with(prefix)) {
                if(!identity.empty()) throw std::runtime_error("MODULE_POLICY_HOOK_ID_DUPLICATE");
                identity=text.substr(prefix.size());
            }
            at+=end-record+1;
        }
    }
    if(!named || !abi || identity.size()<32 || identity.size()>128 || identity.size()%2 ||
       !std::all_of(identity.begin(),identity.end(),[](char c){return (c>='0'&&c<='9') || (c>='a'&&c<='f');}))
        throw std::runtime_error("MODULE_POLICY_HOOK_IDENTITY");
    return identity;
}
}
int policy_hook_loader(int argc,char** argv) {
    using namespace maplesu::module_policy;
    if(getuid() || geteuid()) throw std::runtime_error("MODULE_POLICY_HOOK_ROOT_REQUIRED");
    std::string_view operation(argv[1]);
    if(operation=="hook-info") {
        if(argc!=2) throw std::runtime_error("usage: maplesu-policy hook-info");
        bool present=hook_policy_backend_present();
        // A resident, authenticated backend needs no second image to load and
        // must also work on devices that restrict access to kernel notes.
        auto id=present ? std::string{} : live_id();
        printf("{\"buildId\":\"%s\",\"pageSize\":%ld,\"present\":%s,\"controlAbi\":%u}\n",
            id.c_str(),sysconf(_SC_PAGESIZE),present?"true":"false",MSU_POLICY_HOOK_VERSION);
        return 0;
    }
    if(argc!=4) throw std::runtime_error("usage: maplesu-policy hook-load MODULE BUILD_ID");
    if(hook_policy_backend_present()) {
        puts("{\"loaded\":true,\"existing\":true}");return 0;
    }
    File input(argv[2]);struct stat before{},after{};
    if(fstat(input.fd,&before) || !S_ISREG(before.st_mode) || (before.st_mode&0022) ||
       before.st_size<64 || before.st_size>(4<<20)) throw std::runtime_error("MODULE_POLICY_HOOK_FILE_MODE");
    auto image=contents(input.fd,4<<20);
    if(fstat(input.fd,&after) || before.st_dev!=after.st_dev || before.st_ino!=after.st_ino ||
       before.st_size!=after.st_size || before.st_mtim.tv_sec!=after.st_mtim.tv_sec ||
       before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec || image.size()!=size_t(before.st_size))
        throw std::runtime_error("MODULE_POLICY_HOOK_FILE_CHANGED");
    auto id=live_id();
    if(module_id(image)!=id || id!=argv[3]) throw std::runtime_error("MODULE_POLICY_HOOK_IMAGE_MISMATCH");
    // Pass precisely the validated bytes. init_module is synchronous; no retry
    // follows an interrupt or a lost receipt. QUERY can recover a loaded module.
    auto loaded=syscall(SYS_init_module,image.data(),image.size(),"");
    int error=errno;
    if(loaded && !hook_policy_backend_present())
        throw std::runtime_error("MODULE_POLICY_HOOK_LOAD:"+std::to_string(error));
    if(!hook_policy_backend_present()) throw std::runtime_error("MODULE_POLICY_HOOK_LOAD_READBACK");
    puts("{\"loaded\":true,\"existing\":false}");return 0;
}
