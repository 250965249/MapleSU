#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <cassert>
#include "request_protocol.h"
#include "legacy_hook_private.h"
using u64=uint64_t;using u32=uint32_t;
#ifndef ESTALE
#define ESTALE 116
#endif
#define MSU_MANAGEMENT_NATIVE_TEXT_OWNER 1
#define MSU_MANAGEMENT_SLOTS 64
#define PAGE_SIZE 4096
#define GFP_KERNEL 0
#define PF_EXITING 4
#define noinline
#define __nocfi
#define __builtin_return_address(n) ((void*)fixture_caller)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define raw_spin_lock_irqsave(lock,flags) ((flags)=0)
#define raw_spin_unlock_irqrestore(lock,flags) ((void)(flags))
struct mutex{};struct work_struct{};struct mm_struct{int refs=0;};struct cred{int refs=0;};
struct task_struct{mm_struct* mm;unsigned flags=0,self_exec_id=1;int refs=0;};
struct msu_legacy_gateway{u64 base,bytes,id;};
struct msu_management_session{
 mutex operation;work_struct cleanup;task_struct* task;mm_struct* mm;const cred* original,*active;
 msu_legacy_gateway* legacy_gateway;u64 id,exec_id;u32 principal_uid,epoch,references;
 bool attached,legacy_active,legacy_opened;
};
struct msu_management_resource{bool publication=false;};
struct msu_publication{mutex operation;u64 id;bool legacy,ever_exposed,canceled;msu_management_session* session;};
struct msu_shared_bool{mutex operation;};
struct{maplesu_host_instance host{1,2};maplesu_legacy_hook_provider legacy_provider{};
 msu_management_session* sessions[64]{};msu_legacy_gateway legacy_gateways[64]{};
 u64 next_session=1;unsigned live_sessions=0;bool ready=true,ever_opened=false,legacy_registered=false;
}management;
static mm_struct mm0,mm1;static task_struct task{&mm0};static task_struct* current=&task;
static cred credentials[4];static const cred* active_cred=&credentials[0];static const cred* real_cred=active_cred;
static uintptr_t fixture_caller;static bool sleepable=true,nofault=false,fail_alloc=false;
static unsigned checks=0,releases=0,registrations=0,executes=0;static u32 alloc_flags=0;static int helper_error=0,msu_management_lock;
static void mutex_init(mutex*){}static void mutex_lock(mutex*){}static void mutex_unlock(mutex*){}
static void msu_management_cleanup(work_struct*){}
#define INIT_WORK(work,fn) ((void)(work))
static bool msu_management_sleepable(){return sleepable;}
static int copy_from_kernel_nofault(void*,const void*,size_t){return nofault;}
static void* kzalloc(size_t bytes,int){return fail_alloc?nullptr:calloc(1,bytes);}
static void kfree(void* p){free(p);}
static void get_task_struct(task_struct* t){++t->refs;}static void put_task_struct(task_struct* t){--t->refs;}
static void mmgrab(mm_struct* m){++m->refs;}static void mmdrop(mm_struct* m){--m->refs;}
static const cred* current_cred(){return active_cred;}static const cred* current_real_cred(){return real_cred;}
static const cred* get_cred(const cred* c){++const_cast<cred*>(c)->refs;return c;}
static const cred* get_current_cred(){return get_cred(active_cred);}static void put_cred(const cred* c){--const_cast<cred*>(c)->refs;}
static unsigned current_uid(){return 1012345;}static unsigned __kuid_val(unsigned id){return id;}
static bool msu_management_task_matches(msu_management_session* s){return s->task==current&&s->mm==current->mm&&s->exec_id==current->self_exec_id;}
static void msu_management_put(msu_management_session* s){if(--s->references)return;put_cred(s->active);put_cred(s->original);mmdrop(s->mm);put_task_struct(s->task);--management.live_sessions;free(s);}
static void msu_management_retire(msu_management_session* s){if(!s->attached)return;for(auto& v:management.sessions)if(v==s)v=nullptr;s->attached=false;msu_management_put(s);}
static msu_management_session* msu_management_get(u64 id){for(auto* s:management.sessions)if(s&&s->task==current&&(!id||id==s->id)){++s->references;return s;}return nullptr;}
static int msu_management_check(msu_management_session* s){if(!s->attached||!s->legacy_active||!msu_management_task_matches(s)||s->active!=active_cred||active_cred!=real_cred){msu_management_retire(s);return -ESTALE;}return 0;}
static bool msu_management_host_matches(maplesu_host_instance h){return h.low==management.host.low&&h.high==management.host.high;}
static bool msu_management_shape(u32,const maplesu_management_v3* v){return !v->reserved;}
static int msu_management_release_all(msu_management_session*,u32* effects){++releases;*effects|=MAPLESU_EFFECT_RELEASED;return helper_error;}
static int msu_management_alloc(msu_management_session*,const maplesu_management_v3* value,maplesu_response_owner_v3* r){alloc_flags=value->flags;r->result=0xffff000000010000ULL;r->metadata_address=12;r->metadata_length=MAPLESU_EFFECT_ALLOCATED;return helper_error;}
static int msu_management_exec(msu_management_session*,const maplesu_management_v3*,maplesu_response_owner_v3* r){++executes;r->result=0x123456789abcdef0ULL;return helper_error;}
static int msu_management_write(msu_management_session*,const maplesu_management_v3*,maplesu_response_owner_v3*){return helper_error;}
static unsigned credential_calls=0,procattr_calls=0;static bool credential_root=false;
static int msu_management_credentials(msu_management_session*,const maplesu_management_v3*,bool root,maplesu_response_owner_v3* r){++credential_calls;credential_root=root;r->metadata_length=MAPLESU_EFFECT_COMMITTED;return helper_error;}
static int msu_management_procattr(msu_management_session*,const maplesu_management_v3*,maplesu_response_owner_v3*){++procattr_calls;return helper_error;}
static msu_management_resource resource;
static msu_management_resource* msu_management_resource(msu_management_session*,u64 id){return id==12?&resource:nullptr;}
static int msu_management_release(struct msu_management_resource*,u32* effects){*effects|=MAPLESU_EFFECT_RELEASED;return helper_error;}
static msu_publication publication;static msu_shared_bool shared;
static int msu_publication_prepare(msu_management_session* s,const maplesu_management_v3*,maplesu_response_owner_v3* r){publication={};publication.id=13;publication.session=s;publication.legacy=true;r->result=13;r->metadata_address=0xffff000000020000ULL;r->metadata_length=MAPLESU_EFFECT_PUBLICATION_PREPARED;return helper_error;}
static msu_publication* msu_publication_find(u64 id){return publication.id==id?&publication:nullptr;}
static int msu_publication_publish(msu_management_session*,msu_publication* p,maplesu_response_owner_v3*){p->ever_exposed=true;return helper_error;}
static int msu_publication_disable(msu_publication*,msu_management_session*,maplesu_response_owner_v3*){return helper_error;}
static int msu_publication_retire(msu_publication*,msu_management_session*,maplesu_response_owner_v3*){return helper_error;}
static int msu_publication_release_unexposed(msu_publication*,u32* effects){*effects|=MAPLESU_EFFECT_RELEASED;return helper_error;}
static int msu_shared_bool_create(msu_management_session*,const maplesu_management_v3*,maplesu_response_owner_v3*){return helper_error;}
static int msu_shared_bool_update(msu_management_session*,const maplesu_management_v3*,bool,maplesu_response_owner_v3*){return helper_error;}
static msu_shared_bool* msu_shared_bool_find(u64){return &shared;}
static int msu_shared_bool_drop_creator(msu_shared_bool*,msu_management_session*,u32*){return helper_error;}
static u64 msu_management_capabilities(){return MAPLESU_CAP_SESSION|MAPLESU_CAP_PUBLICATION|MAPLESU_CAP_CODE_RESERVE|MAPLESU_CAP_ALLOC|MAPLESU_CAP_WRITE|MAPLESU_CAP_EXEC|MAPLESU_CAP_RELEASE|MAPLESU_CAP_SHARED_BOOL|MAPLESU_CAP_CREDENTIAL|MAPLESU_CAP_PROCATTR;}
int maplesu_legacy_hook_provider_register(const maplesu_legacy_hook_provider*,const void*){++registrations;return 0;}
int maplesu_legacy_hook_provider_unregister(const void*){--registrations;return 0;}
// EXACT_FUNCTIONS
static void check(bool value){++checks;if(!value){printf("failed check %u\n",checks);exit(2);}}
static void reset(){for(auto* s:management.sessions)if(s){s->legacy_active=false;msu_management_retire(s);}management={};management.host={1,2};management.ready=true;management.next_session=1;sleepable=true;nofault=false;fail_alloc=false;helper_error=0;task.mm=&mm0;task.flags=0;task.self_exec_id=1;active_cred=&credentials[0];real_cred=active_cred;fixture_caller=0xffff000000001010ULL;}
static maplesu_management_v3 op(u64 session=0){maplesu_management_v3 v{};v.host=management.host;v.session=session;return v;}
int main(){
 reset();check(!msu_legacy_hook_bind(4,64));check(!msu_legacy_hook_bind(fixture_caller+4,64));check(!msu_legacy_hook_bind(fixture_caller-16,2));check(!msu_legacy_hook_bind(fixture_caller-16,4097));
 nofault=true;check(!msu_legacy_hook_bind(fixture_caller-16,64));nofault=false;
 u64 gateway=msu_legacy_hook_bind(fixture_caller-16,64);check(gateway==1);check(msu_legacy_hook_bind(fixture_caller-16,64)==gateway);
 fixture_caller+=4096;check(!msu_legacy_hook_begin(gateway));fixture_caller-=4096;
 fail_alloc=true;check(!msu_legacy_hook_begin(gateway));check(management.live_sessions==0);fail_alloc=false;
 u64 scope=msu_legacy_hook_begin(gateway);check(scope&&management.live_sessions==1);check(!msu_legacy_hook_begin(gateway));check(!msu_legacy_hook_end(scope));check(management.live_sessions==0&&!management.ever_opened);check(credentials[0].refs==0&&task.refs==0&&mm0.refs==0);
 scope=msu_legacy_hook_begin(gateway);auto value=op();maplesu_response_owner_v3 response{};
 check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_SESSION_OPEN,&value,&response));check(response.result==scope&&response.completion_magic==MAPLESU_RESPONSE_MAGIC&&management.ever_opened);
 check(!msu_legacy_hook_end(scope));check(management.live_sessions==1);
 check(msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_SESSION_OPEN,&value,&response)==-EPERM);
 active_cred=real_cred=&credentials[1];check(msu_legacy_hook_begin(gateway)==scope);check(credentials[0].refs==1&&credentials[1].refs==1);
 value=op(scope+1);value.flags=MAPLESU_MANAGEMENT_ALLOC_CODE;check(msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_ALLOC,&value,&response)==-EPERM);
 value=op(scope);value.flags=MAPLESU_MANAGEMENT_ALLOC_CODE;check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_ALLOC,&value,&response));check(response.result==0xffff000000010000ULL&&response.metadata_address==12);
 check(alloc_flags==MAPLESU_MANAGEMENT_ALLOC_CODE);value.flags=0;check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_ALLOC,&value,&response));check(alloc_flags==0&&response.result==0xffff000000010000ULL);
 check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_EXEC,&value,&response));check(executes==1&&response.result==0x123456789abcdef0ULL);helper_error=-EFAULT;check(msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_EXEC,&value,&response)==-EFAULT);check(executes==2);helper_error=0;
 helper_error=-ENOMEM;check(msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_ALLOC,&value,&response)==-ENOMEM);check(!response.result&&!response.metadata_address);helper_error=0;
 value=op(scope);check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_CRED_ROOT,&value,&response));check(credential_calls==1&&credential_root&&response.metadata_length==MAPLESU_EFFECT_COMMITTED);
 check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_CRED_CAPS,&value,&response));check(credential_calls==2&&!credential_root);
 check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_CRED_PROCATTR,&value,&response));check(procattr_calls==1);
 check(msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_TASK_STATE,&value,&response)==-EOPNOTSUPP);
 value=op(scope);check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_PUBLICATION_PREPARE,&value,&response));check(response.result==13&&response.metadata_address==0xffff000000020000ULL);
 value.handle=13;check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_PUBLICATION_PUBLISH,&value,&response));check(publication.ever_exposed);
 check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_PUBLICATION_DISABLE,&value,&response));
 helper_error=-EINPROGRESS;check(msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_PUBLICATION_RETIRE,&value,&response)==-EINPROGRESS);helper_error=0;
 check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_PUBLICATION_RETIRE,&value,&response));
 publication.legacy=false;check(msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_PUBLICATION_DISABLE,&value,&response)==-ESTALE);publication.legacy=true;
 value=op(scope);value.flags=MAPLESU_MANAGEMENT_WRITE_TEXT;check(msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_WRITE,&value,&response)==-EINVAL);
 value=op(scope);value.host.high=99;check(msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_SHARED_BOOL_CREATE,&value,&response)==-EINVAL);
 value=op();check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_SESSION_CLOSE,&value,&response));check(response.metadata_length&MAPLESU_EFFECT_SESSION_CLOSED);check(management.live_sessions==0);check(!msu_legacy_hook_end(scope));check(!credentials[0].refs&&!credentials[1].refs&&!task.refs&&!mm0.refs);
 scope=msu_legacy_hook_begin(gateway);value=op();check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_SESSION_OPEN,&value,&response));check(!msu_legacy_hook_end(scope));task.mm=&mm1;check(!msu_legacy_hook_begin(gateway));task.mm=&mm0;
 check(msu_legacy_hook_begin(gateway)==scope);active_cred=real_cred=&credentials[2];value=op(scope);check(msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_PUBLICATION_PREPARE,&value,&response)==-ESTALE);check(management.live_sessions==0);
 check(response.metadata_length&MAPLESU_EFFECT_SESSION_CLOSED);
 scope=msu_legacy_hook_begin(gateway);value=op();check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_SESSION_OPEN,&value,&response));check(!msu_legacy_hook_end(scope));check(management.live_sessions==1);
 check(msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_SESSION_CLOSE,&value,&response)==-EPERM);check(management.live_sessions==1);
 check(msu_legacy_hook_dispatch(scope+1,MAPLESU_REQUEST_SESSION_CLOSE,&value,&response)==-ESTALE);check(management.live_sessions==1);
 value=op(scope);check(msu_legacy_hook_dispatch(scope,MAPLESU_REQUEST_ALLOC,&value,&response)==-EPERM);check(msu_legacy_hook_dispatch(scope,MAPLESU_REQUEST_EXEC,&value,&response)==-EPERM);
 task_struct other{&mm0};current=&other;check(msu_legacy_hook_dispatch(scope,MAPLESU_REQUEST_SESSION_CLOSE,&value,&response)==-ESTALE);check(!(response.metadata_length&MAPLESU_EFFECT_SESSION_CLOSED)&&management.live_sessions==1);current=&task;
 unsigned release_before=releases;active_cred=real_cred=&credentials[3];value=op();check(!msu_legacy_hook_dispatch(scope,MAPLESU_REQUEST_SESSION_CLOSE,&value,&response));check((response.metadata_length&MAPLESU_EFFECT_SESSION_CLOSED)&&(response.metadata_length&MAPLESU_EFFECT_RELEASED));check(management.live_sessions==0&&releases==release_before+1);check(!task.refs&&!mm0.refs&&!credentials[0].refs&&!credentials[1].refs&&!credentials[2].refs&&!credentials[3].refs);
 scope=msu_legacy_hook_begin(gateway);value=op();check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_SESSION_OPEN,&value,&response));check(!msu_legacy_hook_end(scope));task.mm=&mm1;check(msu_legacy_hook_dispatch(scope,MAPLESU_REQUEST_SESSION_CLOSE,&value,&response)==-ESTALE);check((response.metadata_length&MAPLESU_EFFECT_SESSION_CLOSED)&&management.live_sessions==0);task.mm=&mm0;
 scope=msu_legacy_hook_begin(gateway);value=op();check(!msu_legacy_hook_dispatch(0,MAPLESU_REQUEST_SESSION_OPEN,&value,&response));check(!msu_legacy_hook_end(scope));helper_error=-EIO;check(msu_legacy_hook_dispatch(scope,MAPLESU_REQUEST_SESSION_CLOSE,&value,&response)==-EIO);check((response.metadata_length&MAPLESU_EFFECT_SESSION_CLOSED)&&response.status==-EIO&&management.live_sessions==0);helper_error=0;
 reset();for(unsigned i=0;i<64;++i){fixture_caller=0xffff000000001010ULL+i*128;check(msu_legacy_hook_bind(fixture_caller-16,64)==i+1);}fixture_caller+=128;check(!msu_legacy_hook_bind(fixture_caller-16,64));
 check(!msu_legacy_hook_init()&&management.legacy_registered&&registrations==1);check(management.legacy_provider.capabilities&MAPLESU_CAP_EXEC);check((management.legacy_provider.capabilities&MAPLESU_KEY_CREDENTIAL_QUERY)==(MAPLESU_CAP_CREDENTIAL|MAPLESU_CAP_PROCATTR));check(!msu_legacy_hook_shutdown()&&!management.legacy_registered&&!registrations);check(!msu_legacy_hook_shutdown());
 printf("%u checks passed; exact Legacy provider, kernel APIs are seams\n",checks);
}
