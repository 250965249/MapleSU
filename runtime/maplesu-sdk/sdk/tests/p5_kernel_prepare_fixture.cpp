// Executes the real prepare_snapshot and cancel body. Resource/VM/text APIs are seams.
#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <set>
#include "request_protocol.h"
#include "publication_return_private.h"
using u64=std::uint64_t;using u32=std::uint32_t;using u8=std::uint8_t;
constexpr int ESTALE=116;
constexpr unsigned MSU_MANAGEMENT_SLOTS=64,PAGE_SIZE=4096,GFP_KERNEL=1;
enum { MSU_MANAGEMENT_VMALLOC=0,MSU_MANAGEMENT_MODULE=1 };
struct mutex { bool locked=false; };
struct work_struct { bool busy=false; };
void mutex_lock(mutex* value){assert(!value->locked);value->locked=true;}
void mutex_unlock(mutex* value){assert(value->locked);value->locked=false;}
bool mutex_trylock(mutex* value){if(value->locked)return false;value->locked=true;return true;}
bool work_busy(work_struct* value){return value->busy;}
mutex text_mutex;
struct list_head { list_head* next;list_head* prev; };
#define INIT_LIST_HEAD(head) do{(head)->next=(head);(head)->prev=(head);}while(0)
struct task_struct {};struct module { unsigned references=0;bool live=true; } target,other_target;
unsigned target_mode=0;
void preempt_disable(){}void preempt_enable(){}
bool core_kernel_text(u64){return !target_mode;}
module* __module_text_address(u64 address){return target_mode==2?nullptr:target_mode==3&&(address&4)?&other_target:&target;}
bool try_module_get(module* value){if(!value->live)return false;++value->references;return true;}
void module_put(module* value){assert(value->references);--value->references;}
struct msu_management_session { u32 epoch=2;void* legacy_gateway=nullptr; };
struct msu_runtime_service {};
struct msu_publication;
struct msu_management_resource {
    msu_publication* publication=nullptr;void* address=nullptr;u32 bytes=4096;unsigned backend=MSU_MANAGEMENT_MODULE;
};
struct msu_shared_bool { mutex operation;bool creator_reference=false;msu_management_session* creator=nullptr; };
struct msu_publication_member { msu_management_resource* resource;msu_shared_bool* shared_bool;u32 role; };

// EXACT_STRUCTS

#define memset_after(object,value,member) std::memset((char*)(object)+offsetof(msu_publication,member)+sizeof((object)->member),value,sizeof(*(object))-offsetof(msu_publication,member)-sizeof((object)->member))

struct { msu_publication publications[MSU_MANAGEMENT_SLOTS];u64 next_publication=1; } management;
unsigned msu_management_lock;
#define raw_spin_lock_irqsave(lock,flags) do{(void)(lock);(flags)=0;}while(0)
#define raw_spin_unlock_irqrestore(lock,flags) do{(void)(lock);(void)(flags);}while(0)
#define READ_ONCE(value) (value)
std::set<void*> allocations;
bool fail_pool=false,fail_control=false;
void* vmalloc(std::size_t bytes){if(fail_control)return nullptr;void* p=std::calloc(1,bytes);assert(p);allocations.insert(p);return p;}
void* kcalloc(std::size_t n,std::size_t bytes,unsigned){if(fail_pool)return nullptr;void* p=std::calloc(n,bytes);assert(p);allocations.insert(p);return p;}
void kfree(void* p){if(!p)return;assert(allocations.erase(p));std::free(p);}
int set_memory_nx(uintptr_t,unsigned){return 0;}
int set_memory_ro(uintptr_t,unsigned){return 0;}
msu_management_resource resources[2];
msu_management_resource* msu_management_resource_domain(msu_management_session*,msu_runtime_service*,u64 id){return id>=1&&id<=2?&resources[id-1]:nullptr;}
int msu_publication_descriptor_check(const maplesu_publication_prepare_v3*){return 0;}
bool msu_runtime_service_entry(msu_runtime_service*,u64){return true;}
bool msu_publication_code(u32 role){return role==MAPLESU_PUBLICATION_GATE_CODE||role==MAPLESU_PUBLICATION_PAYLOAD_CODE;}
int msu_shared_bool_acquire_domain(msu_management_session*,msu_runtime_service*,u64,u64,msu_shared_bool**){return -EINVAL;}
int msu_management_construction_check(msu_management_session*,msu_runtime_service*){return 0;}
int msu_shared_bool_drop_creator(msu_shared_bool*,msu_management_session*,u32*){return 0;}
bool msu_management_branch(u64,u64,u32* result){*result=0x14000004;return true;}
u64 msu_publication_enter(u64){return 0;}void msu_publication_leave(u64){}
u64 msu_private_return_owner_acquire(u64,u64,u64,u64){return 0;}
void msu_private_return_owner_release(u64){}
u64 msu_private_return_caller_x28(u64){return 0;}u64 msu_private_return_caller_lr(u64){return 0;}
int msu_private_return_status(u64,int*,u64*){return 0;}
int msu_private_actor_attach(u64,u64,u64,u32){return 0;}
u64 msu_private_return_payload(u64){return 0;}
int msu_shared_bool_put(msu_shared_bool*,u32*){return 0;}
int msu_management_release(msu_management_resource* resource,u32* effects){resource->publication=nullptr;*effects|=MAPLESU_EFFECT_RELEASED;return 0;}
int msu_publication_release_control(msu_publication* publication,u32* effects){kfree(publication->control);publication->control=nullptr;*effects|=MAPLESU_EFFECT_RELEASED;return 0;}
void msu_private_actor_release(msu_publication*){}
static int msu_publication_release_unexposed(msu_publication*,u32*);

// EXACT_FUNCTIONS

int main(){
    unsigned checks=0;
    auto check=[&](bool yes,const char* name){++checks;if(!yes){std::cerr<<name<<"\n";std::abort();}};
    msu_management_session session;
    resources[0].address=(void*)0xffff000001000000ULL;
    resources[1].address=(void*)0xffff000001100000ULL;
    maplesu_publication_prepare_v3 descriptor{};
    descriptor.member_count=2;descriptor.gate_index=0;descriptor.entry_address=0xffff000000300000ULL;
    descriptor.payload_entry=(u64)(uintptr_t)resources[1].address;descriptor.expected_instruction=0xd503201f;
    maplesu_publication_member_v3 members[2]{};
    members[0].handle=1;members[0].role=MAPLESU_PUBLICATION_GATE_CODE;
    members[1].handle=2;members[1].role=MAPLESU_PUBLICATION_PAYLOAD_CODE;
    u64 prior=0;
    for(unsigned iteration=0;iteration<130;++iteration){
        maplesu_response_owner_v3 response{};
        check(msu_publication_prepare_snapshot(&session,nullptr,&descriptor,members,&response)==0,"actual prepare repeats after cancel");
        auto& p=management.publications[0];
        check(response.result>prior&&response.result==p.id,"new monotonically increasing publication id");prior=response.result;
        check(p.private_return_pool&&p.control&&!p.references&&!p.private_return_count,"new complete pool/control");
        check(msu_publication_release_unexposed(&p,&response.metadata_length)==0,"real unpublished cancellation");
        check(!p.control&&!p.private_return_pool&&p.payload_released&&allocations.empty(),"cancel reclaims resources for reuse");
    }
    // A retired exposed slot with complete drain uses the same exact reuse branch.
    auto& slot=management.publications[0];slot.ever_exposed=true;slot.entry_restored=slot.entry_drained=slot.gate_drained=true;
    maplesu_response_owner_v3 response{};
    check(msu_publication_prepare_snapshot(&session,nullptr,&descriptor,members,&response)==0&&response.result>prior,"drained exposed slot reused");
    check(msu_publication_release_unexposed(&slot,&response.metadata_length)==0,"reused slot can cancel");
    for(auto& p:management.publications){p.reserved=true;p.payload_released=true;p.entry_restored=p.entry_drained=p.gate_drained=true;p.ever_exposed=true;p.control=nullptr;p.private_return_pool=nullptr;}
    for(auto& p:management.publications)p.cleanup.busy=true;
    response={};check(msu_publication_prepare_snapshot(&session,nullptr,&descriptor,members,&response)==-ENOSPC,"busy cleanup prevents slot reuse");
    for(auto& p:management.publications){p.cleanup.busy=false;p.operation.locked=true;}
    response={};check(msu_publication_prepare_snapshot(&session,nullptr,&descriptor,members,&response)==-ENOSPC,"busy operation prevents slot reuse");
    for(auto& p:management.publications)p.operation.locked=false;
    fail_pool=true;response={};check(msu_publication_prepare_snapshot(&session,nullptr,&descriptor,members,&response)==-ENOMEM&&allocations.empty(),"pool allocation failure cancels actual prepare");fail_pool=false;
    fail_control=true;response={};check(msu_publication_prepare_snapshot(&session,nullptr,&descriptor,members,&response)==-ENOMEM&&allocations.empty(),"control allocation failure cancels pool");fail_control=false;
    target_mode=1;response={};
    check(msu_publication_prepare_snapshot(&session,nullptr,&descriptor,members,&response)==0,"module target prepares with actual pin");
    check(slot.target_module==&target&&target.references==1,"target lease spans prepare through publish");
    check(msu_publication_release_unexposed(&slot,&response.metadata_length)==0&&!target.references&&!slot.target_module,"unpublished cancel puts exact target module");
    members[0].reserved=1;response={};
    check(msu_publication_prepare_snapshot(&session,nullptr,&descriptor,members,&response)==-EINVAL&&!target.references,"validation failure returns temporary target lease");members[0].reserved=0;
    fail_pool=true;response={};
    check(msu_publication_prepare_snapshot(&session,nullptr,&descriptor,members,&response)==-ENOMEM&&!target.references,"failed pool releases reserved target lease");fail_pool=false;
    target.live=false;response={};
    check(msu_publication_prepare_snapshot(&session,nullptr,&descriptor,members,&response)==-ENODEV&&!target.references&&allocations.empty(),"unloading module rejects before closure allocation");target.live=true;
    for(unsigned mode:{2,3}){target_mode=mode;response={};check(msu_publication_prepare_snapshot(&session,nullptr,&descriptor,members,&response)==-EOPNOTSUPP&&!target.references&&!other_target.references,"unknown or cross-module target rejects without lease");}
    std::cout<<"checks="<<checks<<" passed=1 prepareKernelSeams=1\n";
}
