// Exact production retire algorithm; text/grace/allocator operations are seams.
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <iostream>
#include <string>
#include <vector>
#include "request_protocol.h"
using u32=std::uint32_t;
constexpr int ESTALE=116;
struct msu_management_session {};
struct msu_management_resource { unsigned id; };
struct msu_shared_bool {};
struct module {} target;
struct member { msu_management_resource* resource=nullptr;msu_shared_bool* shared_bool=nullptr; };
struct msu_publication {
    bool ever_exposed=true,canceled=false,quarantined=false,payload_released=false;
    bool enabled=true,retire_requested=false,entry_drained=false,gate_drained=false,entry_restored=false;
    unsigned count=2,references=0,private_return_count=0;
    msu_management_session* session=nullptr;
    member members[3];
    void* private_return_pool=nullptr;
    module* target_module=nullptr;
};
unsigned msu_management_lock;
#define raw_spin_lock_irqsave(lock,flags) do { (void)(lock);(flags)=0; } while(0)
#define raw_spin_unlock_irqrestore(lock,flags) do { (void)(lock);(void)(flags); } while(0)
#define READ_ONCE(value) (value)
std::vector<std::string> events;
int disable_error=0,grace_error_at=0,release_error_at=0,control_error=0;
unsigned grace_calls=0,releases=0,actor_releases=0,pool_releases=0,target_releases=0;
int msu_publication_release_unexposed(msu_publication*,u32* effects){events.push_back("unexposed");*effects|=MAPLESU_EFFECT_RELEASED;return 0;}
int msu_publication_disable(msu_publication* p,msu_management_session*,maplesu_response_owner_v3* r){
    assert(!p->enabled&&p->retire_requested);events.push_back("disable");
    r->metadata_length|=MAPLESU_EFFECT_PUBLICATION_RETAINED|MAPLESU_EFFECT_GATE_PINNED;
    if(disable_error)return disable_error;p->entry_restored=true;return 0;
}
int msu_publication_gate_grace(){events.push_back("grace");++grace_calls;return grace_calls==unsigned(grace_error_at)?-EAGAIN:0;}
int msu_shared_bool_put(msu_shared_bool*,u32* effects){events.push_back("shared");*effects|=MAPLESU_EFFECT_REFERENCE_DROPPED;return 0;}
int msu_management_release(msu_management_resource* resource,u32* effects){events.push_back("resource"+std::to_string(resource->id));++releases;*effects|=MAPLESU_EFFECT_RELEASED;return releases==unsigned(release_error_at)?-EIO:0;}
int msu_publication_release_control(msu_publication*,u32*){events.push_back("control");return control_error;}
void kfree(void* p){assert(p);events.push_back("pool");++pool_releases;}
void msu_private_actor_release(msu_publication*){events.push_back("actor");++actor_releases;}
void module_put(module* value){assert(value==&target);events.push_back("target");++target_releases;}

// EXACT_FUNCTION

int main(){
    unsigned checks=0;
    auto check=[&](bool ok,const char* name){++checks;if(!ok){std::cerr<<name<<"\n";std::abort();}};
    msu_management_resource gate{1},payload{2};
    auto setup=[&](){
        events.clear();disable_error=grace_error_at=release_error_at=control_error=0;
        grace_calls=releases=actor_releases=pool_releases=target_releases=0;
        msu_publication p;p.members[0].resource=&gate;p.members[1].resource=&payload;
        p.private_return_pool=&p;p.target_module=&target;return p;
    };
    auto p=setup();maplesu_response_owner_v3 response{};
    p.references=p.private_return_count=1;
    check(msu_publication_retire(&p,nullptr,&response)==-EINPROGRESS,"sleeping original is pending");
    check(!p.enabled&&p.retire_requested&&p.entry_drained&&!p.gate_drained,"entry grace precedes reference check");
    check(releases==0&&pool_releases==0&&actor_releases==0&&target_releases==0,"sleeping original prevents all free including target");
    check(response.metadata_length&MAPLESU_EFFECT_PENDING,"pending receipt retained");
    p.references=p.private_return_count=0;response={};
    check(msu_publication_retire(&p,nullptr,&response)==0,"completed original may retire");
    check(grace_calls==2&&releases==2&&pool_releases==1&&actor_releases==1,"both grace phases then all resources free");
    check(p.payload_released&&!p.private_return_pool&&!p.target_module&&target_releases==1,"pool and target ownership cleared on success");
    check((response.metadata_length&(MAPLESU_EFFECT_RELEASED|MAPLESU_EFFECT_PENDING|MAPLESU_EFFECT_PUBLICATION_RETAINED|MAPLESU_EFFECT_GATE_PINNED))==MAPLESU_EFFECT_RELEASED,"final receipt is fully released");
    const std::vector<std::string> expected{"disable","grace","disable","grace","resource1","resource2","control","pool","actor","target"};
    check(events==expected,"resource order includes gate/control before pool and actor");
    response={};check(msu_publication_retire(&p,nullptr,&response)==0&&releases==2&&pool_releases==1,"repeated retire is idempotent");
    for(int phase:{1,2}){
        p=setup();response={};grace_error_at=phase;
        check(msu_publication_retire(&p,nullptr,&response)==-EAGAIN,"grace failure propagated");
        check(!releases&&!pool_releases&&!actor_releases&&!target_releases&&!p.payload_released,"grace failure prevents free");
    }
    p=setup();response={};disable_error=-EBUSY;
    check(msu_publication_retire(&p,nullptr,&response)==-EBUSY&&!grace_calls&&!releases&&!target_releases,"entry owner conflict blocks all free");
    for(int resource:{1,2}){
        p=setup();response={};release_error_at=resource;
        check(msu_publication_retire(&p,nullptr,&response)==-EIO,"resource release first error retained");
        check(p.quarantined&&!p.payload_released&&!pool_releases&&!actor_releases&&!target_releases,"resource failure retains pool actor target");
        check(response.metadata_length&MAPLESU_EFFECT_PENDING,"resource failure receipt pending");
    }
    p=setup();response={};control_error=-EFAULT;
    check(msu_publication_retire(&p,nullptr,&response)==-EFAULT,"control release first error retained");
    check(!p.payload_released&&!pool_releases&&!actor_releases&&!target_releases,"control failure retains pool actor target");
    check((response.metadata_length&(MAPLESU_EFFECT_PENDING|MAPLESU_EFFECT_QUARANTINED))==(MAPLESU_EFFECT_PENDING|MAPLESU_EFFECT_QUARANTINED),"control failure quarantine receipt");
    std::cout<<"checks="<<checks<<" passed=1 retirementSeams=1\n";
}
