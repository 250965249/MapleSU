// Exact provider-domain functions; VM, owner/task and locking APIs are seams.
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <iostream>
#include "request_protocol.h"
using u64=std::uint64_t;using u32=std::uint32_t;using u8=std::uint8_t;
constexpr int ESTALE=116;
constexpr unsigned MSU_MANAGEMENT_SLOTS=64,PAGE_SIZE=4096;
struct mutex {bool locked=false;};
void mutex_lock(mutex* x){assert(!x->locked);x->locked=true;}void mutex_unlock(mutex* x){assert(x->locked);x->locked=false;}
struct msu_management_session {void* legacy_gateway=nullptr;bool attached=true;u32 epoch=1;};
struct msu_runtime_service {bool active=true;};
// EXACT_STRUCT
struct {msu_shared_bool shared_bools[MSU_MANAGEMENT_SLOTS];u64 next_shared_bool=1;void* owner=nullptr;} management;
unsigned msu_management_lock;
#define raw_spin_lock_irqsave(lock,flags) do{(void)(lock);(flags)=0;}while(0)
#define raw_spin_unlock_irqrestore(lock,flags) do{(void)(lock);(void)(flags);}while(0)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
u32 owner_epoch=1;bool fail_copy=false;
u32 msu_manager_owner_epoch(void*){return owner_epoch;}
msu_shared_bool* msu_shared_bool_find(u64 id){for(auto& b:management.shared_bools)if(b.reserved&&b.id==id)return &b;return nullptr;}
bool msu_runtime_service_live(msu_runtime_service* service){return service&&service->active;}
bool msu_management_construction_live(msu_management_session* session,msu_runtime_service* service){return session?session->attached:msu_runtime_service_live(service);}
int msu_management_construction_check(msu_management_session* session,msu_runtime_service* service){return msu_management_construction_live(session,service)?0:-ESTALE;}
int msu_management_check(msu_management_session* session){return session->attached&&(session->legacy_gateway||session->epoch==owner_epoch)?0:-ESTALE;}
void* vmalloc(unsigned bytes){auto p=std::calloc(1,bytes);assert(p);return p;}
int set_memory_nx(uintptr_t,unsigned){return 0;}int set_memory_rw(uintptr_t,unsigned){return 0;}
int msu_shared_bool_free(msu_shared_bool* b,u32* effects){if(!b->references&&b->address){std::free(b->address);b->address=nullptr;*effects|=MAPLESU_EFFECT_RELEASED;}return 0;}
int msu_shared_bool_drop_creator(msu_shared_bool* b,msu_management_session* session,u32* effects){if(b->creator_reference&&b->creator!=session)return -EPERM;if(b->creator_reference){b->creator_reference=false;b->creator=nullptr;--b->references;}return msu_shared_bool_free(b,effects);}
int copy_from_user_nofault(void* dst,void* src,unsigned bytes){if(fail_copy)return 1;std::memcpy(dst,src,bytes);return 0;}
// EXACT_FUNCTIONS
int main(){
    unsigned checks=0;auto check=[&](bool yes,const char* name){++checks;if(!yes){std::cerr<<name<<"\n";std::abort();}};
    msu_management_session owner,legacy;legacy.legacy_gateway=&legacy;
    maplesu_response_owner_v3 response{};
    check(msu_shared_bool_create_domain(&legacy,nullptr,0,&response)==0,"Legacy creates shared bool");
    auto* legacy_bool=msu_shared_bool_find(response.metadata_address);check(legacy_bool&&legacy_bool->legacy&&legacy_bool->references==1,"Legacy provenance survives creation");
    u64 legacy_id=legacy_bool->id,legacy_address=legacy_bool->published_address;msu_shared_bool* acquired=nullptr;
    check(msu_shared_bool_acquire_domain(&owner,nullptr,legacy_id,legacy_address,&acquired)==-ESTALE&&!acquired&&legacy_bool->references==1,"Owner same epoch cannot acquire Legacy bool");
    check(msu_shared_bool_acquire_domain(&legacy,nullptr,legacy_id,legacy_address,&acquired)==0&&acquired==legacy_bool&&legacy_bool->references==2,"Legacy closure acquires own bool");
    --legacy_bool->references;owner_epoch=9;
    check(msu_shared_bool_acquire_domain(&legacy,nullptr,legacy_id,legacy_address,nullptr)==0,"Owner epoch changes preserve Legacy closure qualification");
    u8 value=1;maplesu_management_v3 operation{};operation.handle=legacy_id;operation.address=legacy_address;operation.data_user=(u64)(uintptr_t)&value;
    response={};check(msu_shared_bool_update(&legacy,&operation,false,&response)==0&&*legacy_bool->address==1&&response.result==1,"Legacy store works after Owner epoch changes");
    owner.epoch=9;response={};check(msu_shared_bool_update(&owner,&operation,false,&response)==-EPERM&&*legacy_bool->address==1,"Owner cannot store Legacy bool");
    response={};check(msu_shared_bool_update(&owner,&operation,true,&response)==-EPERM&&legacy_bool->references==1,"Owner cannot drop Legacy creator");
    response={};check(msu_shared_bool_create_domain(&owner,nullptr,0,&response)==0,"Owner creates own bool");
    auto* owner_bool=msu_shared_bool_find(response.metadata_address);check(owner_bool&&!owner_bool->legacy,"Owner provenance distinct");
    check(msu_shared_bool_acquire_domain(&legacy,nullptr,owner_bool->id,owner_bool->published_address,nullptr)==-ESTALE,"Legacy cannot acquire Owner bool");
    operation.handle=owner_bool->id;operation.address=owner_bool->published_address;response={};
    check(msu_shared_bool_update(&legacy,&operation,false,&response)==-EPERM&&*owner_bool->address==0,"Legacy cannot store Owner bool");
    check(msu_shared_bool_update(&owner,&operation,false,&response)==0&&*owner_bool->address==1,"Owner own store works");
    owner_epoch=10;response={};check(msu_shared_bool_update(&owner,&operation,false,&response)==-ESTALE,"Owner stale epoch still rejects");owner_epoch=9;
    msu_runtime_service service;response={};check(msu_shared_bool_create_domain(nullptr,&service,0,&response)==0,"trusted factory creates service bool");
    auto* service_bool=msu_shared_bool_find(response.metadata_address);
    check(msu_shared_bool_acquire_domain(nullptr,&service,service_bool->id,service_bool->published_address,&acquired)==0&&acquired==service_bool,"service domain acquires its bool");
    check(msu_shared_bool_acquire_domain(&legacy,nullptr,service_bool->id,service_bool->published_address,nullptr)==-ESTALE,"Legacy cannot borrow Owner service bool");
    msu_runtime_service foreign;check(msu_shared_bool_acquire_domain(nullptr,&foreign,service_bool->id,service_bool->published_address,nullptr)==-ESTALE,"foreign service rejects");
    for(auto& b:management.shared_bools)std::free(b.address);
    std::cout<<"checks="<<checks<<" passed=1 sharedKernelSeams=1\n";
}
