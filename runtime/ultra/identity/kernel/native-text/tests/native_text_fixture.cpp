#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <vector>
#include <string>
#include <functional>
#include <type_traits>
#include "legacy_hook_private.h"

using u32 = uint32_t;
using kprobe_opcode_t = u32;
#define __kprobes
#define CONFIG_ARM64 1
#define CONFIG_OPTPROBES 0
#define IS_ENABLED(x) (x)
#define GFP_KERNEL 0
#define EXPORT_SYMBOL_GPL(x)
#define NOKPROBE_SYMBOL(x)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,y) ((x)=(y))
#define le32_to_cpu(x) (x)
#define cpu_to_le32(x) (x)
#define BRK64_OPCODE_KPROBES 0xd4200080U
#define BRK64_OPCODE_KPROBES_SS 0xd42000a0U
#define KPROBE_TEXT_OWNER_RETAINED 1U
#define KPROBE_TEXT_OWNER_WRITTEN 2U
#define KPROBE_TEXT_OWNER_RELEASED 4U
#define KPROBE_TEXT_OWNER_DISABLED 8U
#define KPROBE_TEXT_OWNER_ATTEMPTED 16U
#define KPROBE_HIT_ACTIVE 1
#define KPROBE_HIT_SS 2
#define KPROBE_HIT_SSDONE 4
#define KPROBE_REENTER 8
#define DAIF_MASK 0x3c0
#define DBG_HOOK_ERROR -1
#define DBG_HOOK_HANDLED 0
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { std::fprintf(stderr,"line %d: %s\n",__LINE__,#x); std::abort(); } } while(0)
#define WARN_ON_ONCE(x) (x)
#define WARN_ON(x) (x)
#define ESTALE 116
#define DEFINE_MUTEX(name) int name
#define DEFINE_RAW_SPINLOCK(name) int name
#define DECLARE_WAIT_QUEUE_HEAD(name) int name
#define BUG() std::abort()
#define pr_warn(...) ((void)0)
#define lockdep_is_held(x) true

struct list_head { list_head *next, *prev; };
#define LIST_HEAD(name) list_head name{&name,&name}
#define FIXTURE_ENTRY(type,p,member) reinterpret_cast<type>(reinterpret_cast<char*>(p)-offsetof(std::remove_pointer_t<type>,member))
#define list_for_each_entry(entry,head,member) \
    for (list_head* fixture_node=(head)->next; \
         fixture_node!=(head) && ((entry)=FIXTURE_ENTRY(decltype(entry),fixture_node,member),true); \
         fixture_node=fixture_node->next)
#define list_for_each_entry_safe(entry,next,head,member) \
    for (list_head *fixture_node=(head)->next,*fixture_next=fixture_node->next; \
         fixture_node!=(head) && ((entry)=FIXTURE_ENTRY(decltype(entry),fixture_node,member),(next)=FIXTURE_ENTRY(decltype(next),fixture_next,member),true); \
         fixture_node=fixture_next,fixture_next=fixture_node->next)
#define list_for_each_entry_rcu(entry,head,node,...) \
    for (list_head* fixture_node=(head)->next; \
         fixture_node!=(head) && ((entry)=reinterpret_cast<kprobe_text_owner*>(reinterpret_cast<char*>(fixture_node)-offsetof(kprobe_text_owner,node)),true); \
         fixture_node=fixture_node->next)
static void list_add_tail_rcu(list_head* node,list_head* head) { node->next=head;node->prev=head->prev;head->prev->next=node;head->prev=node; }
static void list_del_rcu(list_head* node) { node->prev->next=node->next;node->next->prev=node->prev; }
static void list_add_tail(list_head* node,list_head* head) { list_add_tail_rcu(node,head); }
static void list_del(list_head* node) { list_del_rcu(node); }
static void list_move_tail(list_head* node,list_head* head) { list_del(node);list_add_tail(node,head); }
static bool list_empty(list_head* head) { return head->next==head; }
struct task_struct { int references{}; } task_a,task_b;
static task_struct* current=&task_a;
static int raw_locks;
static void get_task_struct(task_struct* task) { CHECK(raw_locks==0);++task->references; }
static void put_task_struct(task_struct* task) { CHECK(raw_locks==0 && task->references>0);--task->references; }
struct module { int references{};bool live{true}; } target_module;
static bool module_target, allocation_failure, read_failure;
static int patch_error, patch_writes, grace_calls;
static bool write_on_error;
static void* kzalloc(size_t size,int) { return allocation_failure?nullptr:std::calloc(1,size); }
static void kfree(void* p) { std::free(p); }
static bool core_kernel_text(unsigned long) { return !module_target; }
static module* __module_text_address(unsigned long) { return &target_module; }
static module* __module_address(unsigned long) { return module_target?&target_module:nullptr; }
static bool try_module_get(module* m) { if(!m->live)return false;++m->references;return true; }
static void module_put(module* m) { CHECK(m->references>0);--m->references; }
static void preempt_disable() {}
static void preempt_enable() {}
static int kprobe_mutex,text_mutex;
static std::vector<int*> mutexes;
#define raw_spin_lock_irqsave(lock,flags) do { CHECK(mutexes.empty() && raw_locks==0);(flags)=0;++raw_locks; } while(0)
#define raw_spin_unlock_irqrestore(lock,flags) do { CHECK(raw_locks==1);--raw_locks; } while(0)
static void mutex_lock(int* p) { CHECK(mutexes.empty() || mutexes.back()!=p);mutexes.push_back(p); }
static void mutex_unlock(int* p) { CHECK(!mutexes.empty() && mutexes.back()==p);mutexes.pop_back(); }
static void cpus_read_lock() { CHECK(mutexes.size()==1 && mutexes[0]==&kprobe_mutex); }
static void cpus_read_unlock() { CHECK(mutexes.size()==1 && mutexes[0]==&kprobe_mutex); }
static void synchronize_rcu() { ++grace_calls;CHECK(mutexes.empty()); }
static std::function<void()> fixture_wait;
static unsigned wakeups;
static void wake_up_all(int*) { ++wakeups; }
#define wait_event(wait,condition) do { CHECK(mutexes.empty() && raw_locks==0);if(!(condition))fixture_wait();CHECK(condition); } while(0)
static int copy_from_kernel_nofault(void* dest,const void* src,size_t n) { if(read_failure)return -EFAULT;std::memcpy(dest,src,n);return 0; }
struct pt_regs { unsigned long pc{},pstate{};unsigned long regs[31]{}; };
static unsigned long instruction_pointer(pt_regs* r) { return r->pc; }
static void instruction_pointer_set(pt_regs* r,unsigned long pc) { r->pc=pc; }
struct kprobe;
struct arch_specific_insn { u32 *xol_insn{}; unsigned long xol_restore{}; struct { void(*handler)(u32,long,pt_regs*){}; } api; };
struct kprobe { u32 *addr{};u32 opcode{};arch_specific_insn ainsn{};int(*pre_handler)(kprobe*,pt_regs*){};void(*post_handler)(kprobe*,pt_regs*,unsigned long){};bool disabled{},gone{},ftrace{},optimized{};int missed{}; };
struct kprobe_ctlblk { int kprobe_status{};struct { kprobe* kp{};int status{}; } prev_kprobe;unsigned long saved_irqflag{}; } ctl;
static kprobe *current_kprobe,*registered_probe;
static bool kprobes_all_disarmed;
#define __this_cpu_write(name,v) ((name)=(v))
static kprobe_ctlblk* get_kprobe_ctlblk() { return &ctl; }
static kprobe* kprobe_running() { return current_kprobe; }
static void reset_current_kprobe() { current_kprobe=nullptr; }
static kprobe* get_kprobe(void* addr) { return registered_probe && registered_probe->addr==addr?registered_probe:nullptr; }
static bool kprobe_gone(kprobe* p) { return p->gone; }
static bool kprobe_ftrace(kprobe* p) { return p->ftrace; }
static bool kprobe_optimized(kprobe* p) { return p->optimized; }
static bool kprobe_disabled(kprobe* p) { return p->disabled; }
static void kprobes_inc_nmissed_count(kprobe* p) { ++p->missed; }
static void dump_kprobe(kprobe*) {}
static int aarch64_insn_patch_text(void** addr,u32* insn,int count) { CHECK(count==1);++patch_writes;if(!patch_error || write_on_error)*static_cast<u32*>(*addr)=*insn;return patch_error; }
static void aarch64_insn_patch_text_nosync(u32* addr,u32 insn) { *addr=insn; }
static u32 slots[2];
static u32* get_insn_slot() { return slots; }
static void free_insn_slot(u32*,int) {}
static bool search_exception_tables(unsigned long) { return false; }
enum probe_insn { INSN_REJECTED,INSN_GOOD_NO_SLOT,INSN_GOOD };
static int decoded;
static void native_simulate(u32,long addr,pt_regs* r) { r->regs[0]+=7;r->pc=addr+4; }
static probe_insn arm_kprobe_decode_opcode(u32*,u32 opcode,arch_specific_insn* a) { decoded=opcode;if(opcode==0x10000000U){a->api.handler=native_simulate;return INSN_GOOD_NO_SLOT;}return INSN_GOOD; }
static int arch_prepare_kprobe_ftrace(kprobe*) { return 42; }
static void simulate_b_bl(u32 insn,long addr,pt_regs* r) { int64_t off=(int64_t(int32_t(insn<<6))>>4);r->pc=addr+off; }
static void post_kprobe_handler(kprobe*,kprobe_ctlblk*,pt_regs*);
static void post_kprobe_handler_selected(kprobe*,kprobe_ctlblk*,pt_regs*,bool);
int arch_kprobe_text_owner_patch(void*,u32);
// EXACT_PROVIDER
// EXACT_ARCH
static int pre_calls,post_calls;
static bool pre_redirect,post_redirect;
static unsigned long post_pc;
static int pre(kprobe*,pt_regs* r) { ++pre_calls;if(pre_redirect){r->pc=0x12340000;return 1;}return 0; }
static void post(kprobe*,pt_regs* r,unsigned long) { ++post_calls;post_pc=r->pc;if(post_redirect)r->pc=0x56780000; }
alignas(16) static u32 text[16];
static const int owner_cookie=1,other_cookie=2;
static constexpr u32 original=0xd503201f, branch=0x14000008;
static void reset() { CHECK(kprobe_text_owners.next==&kprobe_text_owners);std::memset(text,0,sizeof(text));text[0]=original;registered_probe=nullptr;current_kprobe=nullptr;ctl={};pre_calls=post_calls=0;pre_redirect=post_redirect=false;module_target=allocation_failure=read_failure=write_on_error=false;target_module={};patch_error=patch_writes=grace_calls=0;kprobes_all_disarmed=false; }
static kprobe prepare(bool active=true) { kprobe p{};p.addr=text;p.pre_handler=pre;p.post_handler=post;CHECK(arch_prepare_kprobe(&p)==0);CHECK(p.opcode==original);CHECK(decoded==int(original));p.disabled=!active;return p; }
static void stop_release() { u32 effects=0;CHECK(kprobe_text_owner_disable(text,&owner_cookie,&effects)==0);CHECK(effects&KPROBE_TEXT_OWNER_DISABLED);CHECK(kprobe_text_owner_release(text,&owner_cookie,&effects)==0);CHECK(effects==KPROBE_TEXT_OWNER_RELEASED); }
int main() {
    // Hook first: later native prepare must decode the displaced instruction,
    // while native dispatch steps the currently selected logical B.
    reset();u32 e=0,l=0,pw=0;CHECK(kprobe_text_owner_claim(text,original,branch,&owner_cookie,&e)==0);CHECK(text[0]==branch);CHECK(e==(KPROBE_TEXT_OWNER_RETAINED|KPROBE_TEXT_OWNER_ATTEMPTED|KPROBE_TEXT_OWNER_WRITTEN));
    kprobe p=prepare();registered_probe=&p;arch_arm_kprobe(&p);CHECK(text[0]==BRK64_OPCODE_KPROBES);CHECK(kprobe_text_owner_read(text,&l,&pw)==0);CHECK(l==branch && pw==BRK64_OPCODE_KPROBES);
    pt_regs r{};r.pc=reinterpret_cast<unsigned long>(text);CHECK(kprobe_brk_handler(&r,0)==0);CHECK(pre_calls==1 && post_calls==1);CHECK(r.pc==reinterpret_cast<unsigned long>(text)+32);CHECK(post_pc==r.pc);CHECK(current_kprobe==nullptr);CHECK(p.ainsn.xol_restore==reinterpret_cast<unsigned long>(text)+4);
    // Native pre redirection suppresses the Hook; post redirection is preserved.
    pre_redirect=true;r.pc=reinterpret_cast<unsigned long>(text);CHECK(kprobe_brk_handler(&r,0)==0);CHECK(r.pc==0x12340000 && post_calls==1);pre_redirect=false;post_redirect=true;r.pc=reinterpret_cast<unsigned long>(text);CHECK(kprobe_brk_handler(&r,0)==0);CHECK(r.pc==0x56780000 && post_calls==2);post_redirect=false;
    // Native disarm/unregister leave the continuing Hook branch in place.
    arch_disarm_kprobe(&p);p.disabled=true;CHECK(text[0]==branch);p.disabled=false;arch_arm_kprobe(&p);CHECK(text[0]==BRK64_OPCODE_KPROBES);arch_disarm_kprobe(&p);registered_probe=nullptr;arch_remove_kprobe(&p);CHECK(text[0]==branch);stop_release();CHECK(text[0]==original);
    // Native first: Hook publication retains BRK and preserves native XOL for
    // an invocation admitted before publication. Disable returns to that XOL.
    reset();p=prepare();registered_probe=&p;arch_arm_kprobe(&p);CHECK(kprobe_text_owner_claim(text,original,branch,&owner_cookie,&e)==0);CHECK(e==KPROBE_TEXT_OWNER_RETAINED);r={};r.pc=reinterpret_cast<unsigned long>(text);CHECK(kprobe_brk_handler(&r,0)==0);CHECK(r.pc==reinterpret_cast<unsigned long>(text)+32);CHECK(kprobe_text_owner_disable(text,&owner_cookie,&e)==0);CHECK(text[0]==BRK64_OPCODE_KPROBES);CHECK(grace_calls==1);r={};r.pc=reinterpret_cast<unsigned long>(text);r.pstate=0x80;CHECK(kprobe_brk_handler(&r,0)==0);CHECK(r.pc==reinterpret_cast<unsigned long>(slots));CHECK(post_calls==1);r.pc=reinterpret_cast<unsigned long>(&slots[1]);CHECK(kprobe_ss_brk_handler(&r,0)==0);CHECK(r.pc==reinterpret_cast<unsigned long>(text)+4);CHECK(post_calls==2 && r.pstate==0x80);CHECK(kprobe_text_owner_release(text,&owner_cookie,&e)==0);arch_disarm_kprobe(&p);registered_probe=nullptr;CHECK(text[0]==original);
    // A native XOL already in flight is unchanged by publication.
    reset();p=prepare();registered_probe=&p;arch_arm_kprobe(&p);r={};r.pc=reinterpret_cast<unsigned long>(text);CHECK(kprobe_brk_handler(&r,0)==0);CHECK(r.pc==reinterpret_cast<unsigned long>(slots));CHECK(kprobe_text_owner_claim(text,original,branch,&owner_cookie,&e)==0);r.pc=reinterpret_cast<unsigned long>(&slots[1]);CHECK(kprobe_ss_brk_handler(&r,0)==0);CHECK(r.pc==reinterpret_cast<unsigned long>(text)+4);stop_release();arch_disarm_kprobe(&p);registered_probe=nullptr;
    // Reentry skips native callbacks and restores outer per-CPU state, while
    // retaining the logical B destination selected for the inner probe.
    reset();p=prepare();registered_probe=&p;arch_arm_kprobe(&p);CHECK(kprobe_text_owner_claim(text,original,branch,&owner_cookie,&e)==0);kprobe outer{};current_kprobe=&outer;ctl.kprobe_status=KPROBE_HIT_ACTIVE;r={};r.pc=reinterpret_cast<unsigned long>(text);CHECK(kprobe_brk_handler(&r,0)==0);CHECK(r.pc==reinterpret_cast<unsigned long>(text)+32);CHECK(current_kprobe==&outer && ctl.kprobe_status==KPROBE_HIT_ACTIVE);CHECK(p.missed==1 && pre_calls==0 && post_calls==0);current_kprobe=nullptr;stop_release();arch_disarm_kprobe(&p);registered_probe=nullptr;
    // Disabled native registration, arm after Hook, disable while native is
    // disarmed, and module lease release only after the publisher's drain.
    reset();module_target=true;p=prepare(false);registered_probe=&p;CHECK(kprobe_text_owner_claim(text,original,branch,&owner_cookie,&e)==0);CHECK(target_module.references==1 && text[0]==branch);p.disabled=false;arch_arm_kprobe(&p);p.disabled=true;arch_disarm_kprobe(&p);CHECK(text[0]==branch);CHECK(kprobe_text_owner_disable(text,&owner_cookie,&e)==0);CHECK(text[0]==original && target_module.references==1);CHECK(kprobe_text_owner_claim(text,original,branch,&other_cookie,&e)==-EBUSY);CHECK(kprobe_text_owner_release(text,&other_cookie,&e)==-ESTALE);CHECK(target_module.references==1);CHECK(kprobe_text_owner_release(text,&owner_cookie,&e)==0);CHECK(target_module.references==0);registered_probe=nullptr;
    // Real errors retain ownership and release occurs only after reconciliation.
    reset();module_target=true;write_on_error=true;patch_error=-EIO;CHECK(kprobe_text_owner_claim(text,original,branch,&owner_cookie,&e)==-EIO);CHECK(e&KPROBE_TEXT_OWNER_RETAINED);CHECK(text[0]==branch && target_module.references==1);CHECK(kprobe_text_owner_release(text,&owner_cookie,&e)==-EBUSY);patch_error=0;stop_release();CHECK(target_module.references==0);
    reset();allocation_failure=true;CHECK(kprobe_text_owner_claim(text,original,branch,&owner_cookie,&e)==-ENOMEM);CHECK(!e && !patch_writes);allocation_failure=false;text[0]=0xdeadbeef;CHECK(kprobe_text_owner_claim(text,original,branch,&owner_cookie,&e)==-EBUSY);CHECK(!e && !patch_writes);
    // A simulated original keeps its native semantics after disable; native
    // dispatch does not mutate the original register effects while B is live.
    reset();text[0]=0x10000000U;p={};p.addr=text;p.pre_handler=pre;p.post_handler=post;CHECK(arch_prepare_kprobe(&p)==0);CHECK(!p.ainsn.xol_insn && !p.ainsn.xol_restore);registered_probe=&p;arch_arm_kprobe(&p);CHECK(kprobe_text_owner_claim(text,0x10000000U,0x17fffff8U,&owner_cookie,&e)==0);r={};r.pc=reinterpret_cast<unsigned long>(text);CHECK(kprobe_brk_handler(&r,0)==0);CHECK(r.pc==reinterpret_cast<unsigned long>(text)-32 && r.regs[0]==0);CHECK(kprobe_text_owner_disable(text,&owner_cookie,&e)==0);r.pc=reinterpret_cast<unsigned long>(text);CHECK(kprobe_brk_handler(&r,0)==0);CHECK(r.pc==reinterpret_cast<unsigned long>(text)+4 && r.regs[0]==7);CHECK(kprobe_text_owner_release(text,&owner_cookie,&e)==0);arch_disarm_kprobe(&p);registered_probe=nullptr;
    // A ftrace producer has no native B simulator. Reject both installation
    // orders before modifying the text or stealing a third-party probe.
    reset();p=prepare();p.ftrace=true;CHECK(prepare_kprobe(&p)==42);registered_probe=&p;CHECK(kprobe_text_owner_claim(text,original,branch,&owner_cookie,&e)==-EOPNOTSUPP);CHECK(!e && !patch_writes);registered_probe=nullptr;p.ftrace=false;CHECK(kprobe_text_owner_claim(text,original,branch,&owner_cookie,&e)==0);p.ftrace=true;CHECK(prepare_kprobe(&p)==-EOPNOTSUPP);stop_release();CHECK(text[0]==original);
    // The kernel registry owns the real dynamically loaded provider lease.
    // Its wait is a causal seam that performs an in-flight scope's final put.
    reset();const maplesu_legacy_hook_provider* table=nullptr;void* lease=nullptr;
    CHECK(maplesu_legacy_hook_provider_get(&table,&lease)==-ENOENT);CHECK(!table && !lease);
    maplesu_legacy_hook_provider provider{};provider.magic=MAPLESU_LEGACY_HOOK_MAGIC;provider.schema=MAPLESU_LEGACY_HOOK_SCHEMA;provider.length=sizeof(provider);provider.bind_function=1;provider.begin_function=2;provider.end_function=3;provider.dispatch_function=4;
    auto invalid=provider;invalid.length=0;CHECK(maplesu_legacy_hook_provider_register(&invalid,&owner_cookie)==-EINVAL);
    module_target=true;CHECK(maplesu_legacy_hook_provider_register(&provider,&owner_cookie)==0);CHECK(target_module.references==1);CHECK(maplesu_legacy_hook_provider_register(&provider,&other_cookie)==-EBUSY);
    CHECK(maplesu_legacy_hook_provider_get(&table,&lease)==0);CHECK(table==&provider && lease);void* second=nullptr;CHECK(maplesu_legacy_hook_provider_get(&table,&second)==0);CHECK(second!=lease && maplesu_legacy_provider.references==2);
    fixture_wait=[&] { CHECK(maplesu_legacy_provider.draining);CHECK(target_module.references==1);table=&provider;void* denied=lease;CHECK(maplesu_legacy_hook_provider_get(&table,&denied)==-ENOENT);CHECK(!table && !denied);CHECK(maplesu_legacy_hook_provider_unregister(&other_cookie)==-ESTALE);CHECK(maplesu_legacy_hook_provider_unregister(&owner_cookie)==-EINPROGRESS);CHECK(maplesu_legacy_hook_provider_register(&provider,&other_cookie)==-EBUSY);maplesu_legacy_hook_provider_put(lease);CHECK(maplesu_legacy_provider.references==1);maplesu_legacy_hook_provider_put(second);CHECK(maplesu_legacy_provider.references==0);CHECK(wakeups==1); };
    CHECK(maplesu_legacy_hook_provider_unregister(&owner_cookie)==0);CHECK(target_module.references==0);CHECK(!maplesu_legacy_provider.table && !maplesu_legacy_provider.owner);CHECK(maplesu_legacy_hook_provider_get(&table,&lease)==-ENOENT);
    module_target=false;CHECK(maplesu_legacy_hook_provider_register(&provider,&owner_cookie)==0);CHECK(target_module.references==0);maplesu_legacy_provider.references=~0U;CHECK(maplesu_legacy_hook_provider_get(&table,&lease)==-EOVERFLOW);CHECK(!table && !lease);maplesu_legacy_provider.references=0;CHECK(maplesu_legacy_hook_provider_unregister(&owner_cookie)==0);CHECK(task_a.references==0 && task_b.references==0);
    // do_exit abandons both the outer authenticated EXEC lease and recursive
    // dispatch leases. Atomic cleanup removes only that task; unregister keeps
    // waiting for another task's real active scope, then releases the module.
    module_target=true;CHECK(maplesu_legacy_hook_provider_register(&provider,&owner_cookie)==0);allocation_failure=true;CHECK(maplesu_legacy_hook_provider_get(&table,&lease)==-ENOMEM);CHECK(!lease && task_a.references==0 && maplesu_legacy_provider.references==0);allocation_failure=false;
    current=&task_a;void *abandoned_outer=nullptr,*abandoned_inner=nullptr,*normal=nullptr,*other_task=nullptr;
    CHECK(maplesu_legacy_hook_provider_get(&table,&abandoned_outer)==0);CHECK(maplesu_legacy_hook_provider_get(&table,&abandoned_inner)==0);CHECK(maplesu_legacy_hook_provider_get(&table,&normal)==0);CHECK(task_a.references==3);maplesu_legacy_hook_provider_put(normal);CHECK(task_a.references==2);
    current=&task_b;CHECK(maplesu_legacy_hook_provider_get(&table,&other_task)==0);CHECK(task_b.references==1 && maplesu_legacy_provider.references==3);
    maplesu_legacy_hook_provider_put(abandoned_outer);CHECK(maplesu_legacy_provider.references==3);current=&task_a;
    fixture_wait=[&] { CHECK(maplesu_legacy_provider.draining);CHECK(target_module.references==1);maplesu_legacy_hook_provider_task_exit(&task_a);CHECK(task_a.references==0 && task_b.references==1);CHECK(maplesu_legacy_provider.references==1 && target_module.references==1);maplesu_legacy_hook_provider_task_exit(&task_a);CHECK(maplesu_legacy_provider.references==1);current=&task_b;maplesu_legacy_hook_provider_put(other_task);CHECK(task_b.references==0 && maplesu_legacy_provider.references==0); };
    CHECK(maplesu_legacy_hook_provider_unregister(&owner_cookie)==0);CHECK(target_module.references==0);CHECK(list_empty(&maplesu_legacy_provider_leases));CHECK(!raw_locks && mutexes.empty());current=&task_a;
    std::printf("native producer checks: %u passed\n",checks);
}
