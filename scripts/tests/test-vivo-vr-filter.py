#!/usr/bin/env python3
"""Execute the production ELF reader, syscall wrappers and hook failure paths on the host."""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "third_party/kernelsu/applied/kernel/hook/init_module_filter.c"

STUBS = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#define __aarch64__ 1
#define MODULE 1
#define __user
#define __init
#define __exit
#define GFP_KERNEL 0
#define ELFMAG "\177ELF"
#define SELFMAG 4
#define EI_CLASS 4
#define EI_DATA 5
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define EM_AARCH64 183
#define ET_REL 1
#define __NR_init_module 0
#define __NR_finit_module 1
#define PT_REGS_PARM1(r) ((r)->args[0])
#define PT_REGS_PARM2(r) ((r)->args[1])
#define READ_ONCE(x) (x)
#define module_param_named(...)
#define MODULE_PARM_DESC(...)
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
#define kmalloc(n, flags) malloc(n)
#define kfree(p) free(p)
#define THIS_MODULE ((void *)1)
#define KSU_FEATURE_VR_FILTER 7
typedef uint64_t u64;
typedef struct { unsigned char e_ident[16]; uint16_t e_type,e_machine; uint32_t e_version;
    uint64_t e_entry,e_phoff,e_shoff; uint32_t e_flags;
    uint16_t e_ehsize,e_phentsize,e_phnum,e_shentsize,e_shnum,e_shstrndx; } Elf64_Ehdr;
typedef struct { uint32_t sh_name,sh_type; uint64_t sh_flags,sh_addr,sh_offset,sh_size;
    uint32_t sh_link,sh_info; uint64_t sh_addralign,sh_entsize; } Elf64_Shdr;
struct pt_regs { uintptr_t args[6]; };
typedef long (*syscall_fn_t)(const struct pt_regs *);
struct file { const unsigned char *data; int64_t size; };
static struct file fixture_file;
static int copy_failure, file_failure, original_calls, fget_calls, fput_calls, pins;
static int install_failure, rollback_failure;
static long original(const struct pt_regs *r) { original_calls++; return -73; }
static syscall_fn_t table[2], saved[2];
static syscall_fn_t *ksu_syscall_table = table;
static int copy_from_user(void *out, const void *in, size_t n) {
    if(copy_failure) return 1; memcpy(out,in,n); return 0;
}
static struct file *fget(int fd) { if(fd!=19) return NULL; fget_calls++; return &fixture_file; }
static void fput(struct file *f) { fput_calls++; }
#define file_inode(f) (f)
#define i_size_read(f) ((f)->size)
static ptrdiff_t kernel_read(struct file *f, void *out, size_t n, int64_t *pos) {
    if(file_failure) return -EIO; memcpy(out,f->data+*pos,n); *pos+=n; return n;
}
struct ksu_feature_handler { unsigned int feature_id; const char *name;
    int (*get_handler)(u64 *); int (*set_handler)(u64); };
static const struct ksu_feature_handler *status_handler;
static int ksu_register_feature_handler(const struct ksu_feature_handler *h) { status_handler=h; return 0; }
static void __module_get(void *m) { pins++; }
static void ksu_syscall_table_hook(int nr, syscall_fn_t fn, syscall_fn_t *old) {
    saved[nr]=table[nr]; *old=table[nr]; if(!(install_failure & (1<<nr))) table[nr]=fn;
}
static void ksu_syscall_table_unhook(int nr) {
    if(!(rollback_failure & (1<<nr))) table[nr]=saved[nr];
}
'''

TESTS = r'''
static int checks;
#define CHECK(x) do { checks++; if(!(x)) { fprintf(stderr,"check failed at line %d: %s\n",__LINE__,#x); return 1; } } while(0)
static void image(unsigned char *data, const char *name) {
    memset(data,0,1024);
    Elf64_Ehdr *e=(void *)data;
    memcpy(e->e_ident,ELFMAG,4); e->e_ident[EI_CLASS]=ELFCLASS64; e->e_ident[EI_DATA]=ELFDATA2LSB;
    e->e_machine=EM_AARCH64; e->e_type=ET_REL;
    e->e_shoff=64; e->e_shentsize=sizeof(Elf64_Shdr); e->e_shnum=3; e->e_shstrndx=1;
    Elf64_Shdr *s=(void *)(data+64);
    s[1].sh_offset=256; s[1].sh_size=21;
    memcpy(data+256,"\0.shstrtab\0.modinfo\0",20);
    s[2].sh_name=11; s[2].sh_offset=300;
    s[2].sh_size=snprintf((char *)data+300,100,"name=%s",name)+1;
}
static void reset_hooks(int install, int rollback) {
    ksu_syscall_table=table; table[0]=table[1]=original;
    install_failure=install; rollback_failure=rollback; pins=0; vr_filter_active=false;
}
int main(void) {
    unsigned char data[1024]; struct pt_regs regs={0};
    orig_sys_init_module=original; orig_sys_finit_module=original;
    regs.args[0]=(uintptr_t)data; regs.args[1]=sizeof(data);
    image(data,"vr"); CHECK(ksu_sys_init_module(&regs)==0); CHECK(original_calls==0);
    const char *others[]={"vklp","vrouter","VR","vr_", ""};
    for(unsigned int i=0;i<sizeof(others)/sizeof(*others);i++) {
        image(data,others[i]); CHECK(ksu_sys_init_module(&regs)==-73);
    }
    image(data,"vr"); copy_failure=1; CHECK(ksu_sys_init_module(&regs)==-73); copy_failure=0;
    regs.args[1]=63; CHECK(ksu_sys_init_module(&regs)==-73); regs.args[1]=sizeof(data);
    Elf64_Ehdr *e=(void *)data; Elf64_Shdr *s=(void *)(data+64);
    e->e_shnum=513; CHECK(ksu_sys_init_module(&regs)==-73); image(data,"vr");
    e->e_shoff=UINT64_MAX; CHECK(ksu_sys_init_module(&regs)==-73); image(data,"vr");
    e->e_machine=62; CHECK(ksu_sys_init_module(&regs)==-73); image(data,"vr");
    e->e_ident[EI_CLASS]=1; CHECK(ksu_sys_init_module(&regs)==-73); image(data,"vr");
    e->e_ident[EI_DATA]=2; CHECK(ksu_sys_init_module(&regs)==-73); image(data,"vr");
    s[2].sh_size=7; CHECK(ksu_sys_init_module(&regs)==-73); image(data,"vr");
    s[2].sh_offset=1020; s[2].sh_size=8; CHECK(ksu_sys_init_module(&regs)==-73); image(data,"vr");
    memset(data+256,'x',21); CHECK(ksu_sys_init_module(&regs)==-73); image(data,"vr");
    fixture_file=(struct file){data,sizeof(data)}; regs.args[0]=19;
    CHECK(ksu_sys_finit_module(&regs)==0); CHECK(fget_calls==fput_calls && fget_calls==1);
    image(data,"vklp"); CHECK(ksu_sys_finit_module(&regs)==-73);
    image(data,"vr"); file_failure=1; CHECK(ksu_sys_finit_module(&regs)==-73); file_failure=0;
    regs.args[0]=20; CHECK(ksu_sys_finit_module(&regs)==-73); CHECK(fget_calls==fput_calls);
    u64 value;
    reset_hooks(0,0); ksu_init_module_filter_init();
    CHECK(ksu_init_module_filter_active()); CHECK(pins==1);
    CHECK(status_handler && status_handler->feature_id==7);
    CHECK(status_handler->get_handler(&value)==0 && value==1);
    reset_hooks(2,0); ksu_init_module_filter_init();
    CHECK(!ksu_init_module_filter_active() && pins==0); CHECK(table[0]==original && table[1]==original);
    reset_hooks(2,1); ksu_init_module_filter_init();
    CHECK(!ksu_init_module_filter_active() && pins==1); CHECK(table[0]==ksu_sys_init_module);
    CHECK(status_handler->get_handler(&value)==0 && value==0);
    reset_hooks(3,0); ksu_init_module_filter_init(); CHECK(!ksu_init_module_filter_active() && pins==0);
    reset_hooks(0,0); ksu_syscall_table=NULL; ksu_init_module_filter_init(); CHECK(!vr_filter_active && pins==0);
    printf("vr filter: %d checks passed\n",checks); return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--out", type=Path, default=ROOT / ".analysis/vivo-implementation-20261109/filter-harness")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    production = re.sub(r"^#include[^\n]*", "", SOURCE.read_text(encoding="utf-8"), flags=re.M)
    production = production.replace("loff_t", "int64_t").replace("ssize_t", "ptrdiff_t")
    source, binary = args.out / "filter.c", args.out / "filter.exe"
    source.write_text(STUBS + production + TESTS, encoding="utf-8")
    subprocess.run([args.cc, "-std=gnu11", "-O2", str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
    print("production source sha256:", hashlib.sha256(SOURCE.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
