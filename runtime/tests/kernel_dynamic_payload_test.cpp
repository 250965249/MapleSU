#include "kernel_payload_io_fixture.h"
#include "policy_layout_slots.h"
#include "compiled-layout.h"
#include <cstdio>
#include <fstream>
#include <iterator>
#include <set>
using Table = maplesu_policy_layout_table;
extern "C" {
void dynamic_access_bind(const Table *);
uint32_t dynamic_access_uid(void *);
uint32_t dynamic_access_sid(void *, int);
void dynamic_access_set_uid(void *, uint32_t);
void *dynamic_access_parent(void *);
void *dynamic_access_context(void *);
uint32_t dynamic_access_policy_flag(const void *);
}
namespace {
unsigned cases;
struct Field { const char *type, *member; bool embedded; };
const Field slots[] = {
#define MP_FIELD(type, member, embedded) {#type,#member,bool(embedded)},
    MAPLESU_POLICY_LAYOUT_FIELDS(MP_FIELD)
    MAPLESU_POLICY_OPTIONAL_LAYOUT_FIELDS(MP_FIELD)
#undef MP_FIELD
};
const Field bit_slots[] = {
#define MP_BIT(type, member) {#type,#member,true},
    MAPLESU_POLICY_LAYOUT_BITS(MP_BIT)
#undef MP_BIT
};
const char *sizes[] = {
#define MP_TYPE(type) #type,
    MAPLESU_POLICY_LAYOUT_TYPES(MP_TYPE)
#undef MP_TYPE
};
std::string alias(const char *name, const std::vector<LayoutType>& layout) {
    if (std::string_view(name)!="maplesu_cred_security") return name;
    for (const auto& type : layout) if (type.name=="task_security_struct" || type.name=="cred_security_struct") return type.name;
    assert(false); return {};
}
const LayoutType& type_at(const std::vector<LayoutType>& layout,const std::string& name) {
    for(const auto& t:layout) if(t.name==name) return t;
    assert(false);return layout.front();
}
const LayoutField& field_at(const std::vector<LayoutType>& layout,const std::string& type,const std::string& member) {
    for(const auto& f:type_at(layout,type).fields) if(f.name==member) return f;
    assert(false);return layout.front().fields.front();
}
void word(std::vector<uint8_t>& v,uint32_t x){for(unsigned i=0;i<4;++i)v.push_back(x>>(i*8));}
std::vector<uint8_t> btf(const std::vector<LayoutType>& layout) {
    std::vector<uint8_t> records,strings{0};unsigned id=0;
    auto name=[&](const std::string& text){auto at=strings.size();strings.insert(strings.end(),text.begin(),text.end());strings.push_back(0);return unsigned(at);};
    auto record=[&](const std::string& text,unsigned kind,unsigned size,unsigned count=0,bool bits=false){
        word(records,name(text));word(records,kind<<24|count|(bits?0x80000000U:0));word(records,size);return ++id;
    };
    record("u8",1,1);word(records,8);
    record("u32",1,4);word(records,32);
    record("u64",1,8);word(records,64);
    for(const auto& type:layout){
        std::vector<unsigned> members;
        bool bits=false;unsigned required_size=type.size;
        for(const auto& f:type.fields){
            const bool bitfield=(f.bit_size%8)||(f.bit_offset%8);bits|=bitfield;
            unsigned n;
            if(bitfield)n=f.bit_size<=8?1:f.bit_size<=32?2:3;
            else {n=record("",3,0);word(records,1);word(records,1);word(records,(f.bit_size+7)/8);}
            members.push_back(n);required_size=std::max(required_size,(f.bit_offset+f.bit_size+7)/8);
        }
        record(type.name,4,std::max(8U,required_size),members.size(),bits);
        for(unsigned i=0;i<members.size();++i){const auto& f=type.fields[i];word(records,name(f.name));word(records,members[i]);
            word(records,f.bit_offset|(((f.bit_size%8)||(f.bit_offset%8))?f.bit_size<<24:0));}
    }
    std::vector<uint8_t> result;
    for(auto v:{0x1eb9fU,24U,0U,unsigned(records.size()),unsigned(records.size()),unsigned(strings.size())})word(result,v);
    result.insert(result.end(),records.begin(),records.end());result.insert(result.end(),strings.begin(),strings.end());return result;
}
Table table(const PolicyPayload& p){Table t;memcpy(&t,p.image.data()+p.exports.at("maplesu_policy_layout"),sizeof(t));return t;}
std::vector<LayoutType> moved(std::vector<LayoutType> layout){
    for(auto& type:layout){
        unsigned end=type.size*8;
        for(const auto& f:type.fields)end=std::max(end,f.bit_offset+f.bit_size);
        end=(end+255)&~63U;
        for(auto& f:type.fields)for(const auto& s:slots)if(type.name==alias(s.type,layout)&&f.name==s.member){
            f.bit_offset=end;end=(end+f.bit_size+63)&~63U;
        }
        for(auto& f:type.fields)for(const auto& slot:bit_slots)if(type.name==slot.type&&f.name==slot.member){
            f.bit_offset=end+3;end=(end+f.bit_size+127)&~63U;
        }
        if(std::find(std::begin(sizes),std::end(sizes),type.name)!=std::end(sizes))type.size=(end+63)/8;
    }
    for(auto& t:layout)if(t.name=="selinux_policy"){
        unsigned end=(t.size*8+63)&~63U;
        for(auto& f:t.fields){
            if(f.name=="policydb")f.bit_size=type_at(layout,"policydb").size*8;
            f.bit_offset=end;end=(end+f.bit_size+63)&~63U;
        }
        t.size=(end+63)/8;
    }
    // A moved child must still fit its containing control buffer. Model a
    // valid target, rather than overlapping unrelated skb members.
    for(auto& t:layout)if(t.name=="sk_buff"){
        unsigned needed=0,end=0;
        for(const auto& f:type_at(layout,"netlink_skb_parms").fields)needed=std::max(needed,f.bit_offset+f.bit_size);
        for(auto& f:t.fields)if(f.name=="cb")f.bit_size=std::max(f.bit_size,needed);
        for(const auto& f:t.fields)end=std::max(end,f.bit_offset+f.bit_size);
        end=(end+255)&~63U;
        for(auto& f:t.fields){f.bit_offset=end;end=(end+f.bit_size+63)&~63U;}
    }
    return layout;
}
void check_bound(const Table& actual,const std::vector<LayoutType>& target){
    assert(actual.ready==1);
    for(unsigned i=0;i<MP_FIELD_COUNT;++i)if(actual.alignments[i])assert(actual.offsets[i]==field_at(target,alias(slots[i].type,target),slots[i].member).bit_offset/8);
    for(unsigned i=0;i<MP_TYPE_COUNT;++i)assert(actual.sizes[i]==type_at(target,sizes[i]).size);
    for(unsigned i=0;i<MP_BIT_COUNT;++i)if(actual.bit_widths[i]){
        const auto f=field_at(target,bit_slots[i].type,bit_slots[i].member);
        assert(actual.bit_offsets[i]==f.bit_offset&&actual.bit_widths[i]==f.bit_size);
    }
    ++cases;
}
void exercise_access(const Table& bound){
    dynamic_access_bind(&bound);
    std::vector<uint8_t> task(65536,0),cred(65536,0),security(65536,0),parent(65536,0),entry(65536,0);
    auto put=[&](auto& bytes,unsigned slot,const auto& value){assert(bound.offsets[slot]+sizeof(value)<=bytes.size());memcpy(bytes.data()+bound.offsets[slot],&value,sizeof(value));};
    const void *cred_ptr=cred.data(),*security_ptr=security.data(),*parent_ptr=parent.data();
    put(task,MP_FIELD_task_struct_cred,cred_ptr);put(cred,MP_FIELD_cred_security,security_ptr);
    uint32_t uid=10123,sid=701,ptraced=1;
    put(cred,MP_FIELD_cred_uid,uid);
    const int blob_offset=16;memcpy(security.data()+blob_offset+bound.offsets[MP_FIELD_maplesu_cred_security_sid],&sid,4);
    assert(dynamic_access_uid(task.data())==uid);
    assert(dynamic_access_sid(task.data(),blob_offset)==sid);
    dynamic_access_set_uid(cred.data(),10456);uint32_t readback;memcpy(&readback,cred.data()+bound.offsets[MP_FIELD_cred_uid],4);assert(readback==10456);
    put(task,MP_FIELD_task_struct_parent,parent_ptr);put(task,MP_FIELD_task_struct_ptrace,ptraced);
    assert(dynamic_access_parent(task.data())==parent.data());ptraced=0;put(task,MP_FIELD_task_struct_ptrace,ptraced);assert(!dynamic_access_parent(task.data()));
    assert(dynamic_access_context(entry.data())==entry.data()+bound.offsets[MP_FIELD_sidtab_entry_context]);
    std::vector<uint8_t> policy(65536,0);
    const auto bit=bound.bit_offsets[MP_BIT_policydb_allow_unknown];
    policy[bit/8]|=1U<<(bit&7);assert(dynamic_access_policy_flag(policy.data())==1);
    policy[bit/8]=0;assert(!dynamic_access_policy_flag(policy.data()));
    cases+=8;
}
template<class F> void failure(F fn){bool rejected=false;try{fn();}catch(const std::runtime_error&){rejected=true;}assert(rejected);++cases;}
}
int main(int argc,char** argv){
    assert(argc==2||argc==3);std::ifstream input(argv[1],std::ios::binary);assert(input);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),{});
    const auto reference=compiled_layout();const auto original=parse_policy_payload(bytes,4096);
    assert(original.exports.contains("maplesu_policy_layout")&&!table(original).ready);++cases;
    auto baseline=original;assert(bind_policy_payload_layout(baseline,reference,{}));
    check_bound(table(baseline),reference);exercise_access(table(baseline));
    const auto target=moved(reference);const auto target_btf=btf(target);
    failure([&]{verify_kernel_layout(target_btf,reference);});
    auto dynamic=original;assert(bind_policy_payload_layout(dynamic,reference,target_btf));
    check_bound(table(dynamic),target);exercise_access(table(dynamic));
    // Real install path: target table must reach the written kernel image before
    // prepare/any hook/activation. Io calls do not execute a live kernel.
    KernelPolicyBundle bundle{bytes,"fixture-build",4096,false,"caches_clean_inval_pou",{},compiled_layout};
    Io io;io.inspect_prepare=[&](const Io& state){auto p=original;p.image.assign(state.memory.begin(),state.memory.begin()+original.image.size());check_bound(table(p),target);assert(!state.hooks&&!state.activation_enabled);};
    assert(install_policy_view(bundle,"fixture-build",4096,target_btf,io)==3&&io.hooks==9&&io.activation_enabled);++cases;
    Io probe;preflight_policy_view(bundle,"fixture-build",4096,target_btf,probe);
    assert(!probe.allocations&&!probe.hooks&&probe.memory.empty());++cases;
    auto install=[&](Io& state){return install_policy_view(bundle,"fixture-build",4096,target_btf,state);};
    auto inactive_failure=[&](Io& state,unsigned releases){
        failure([&]{install(state);});
        assert(state.allocations==1&&state.releases==releases&&!state.activation_enabled);
    };
    for(unsigned i=0;i<std::size(hook_names);++i){
        Io state;state.bad_dispatch=i;inactive_failure(state,1);assert(!state.hooks&&!state.prepared);
    }
    {Io state;state.inspect_prepare=io.inspect_prepare;state.prepare_error=true;
     inactive_failure(state,0);assert(state.prepared&&!state.hooks&&state.last_phase=="prepare-snapshot");}
    {Io state;state.change_entry_after_prepare=true;inactive_failure(state,0);assert(!state.hooks);}
    for(unsigned i=0;i<std::size(hook_names);++i){
        Io state;state.inspect_prepare=io.inspect_prepare;state.bad_hook=i;inactive_failure(state,0);
        assert(state.hooks==i+1&&std::find(state.events.begin(),state.events.end(),"activate")==state.events.end());
    }
    {Io state;state.inspect_prepare=io.inspect_prepare;state.activation_error=true;inactive_failure(state,0);
     assert(state.hooks==std::size(hook_names)&&state.events.back()=="deactivate");}
    {Io state;state.bad_readback=true;inactive_failure(state,0);assert(!state.prepared&&!state.hooks);}
    {Io state;auto bad=bundle;bad.layout=nullptr;
     failure([&]{install_policy_view(bad,"fixture-build",4096,target_btf,state);});assert(!state.allocations&&!state.hooks);}
    auto empty=reference;empty.pop_back();failure([&]{auto p=original;bind_policy_payload_layout(p,empty,{});});
    for(unsigned delta:{0U,4U,8U,12U,16U,20U}){auto p=original;p.image[p.exports.at("maplesu_policy_layout")+delta]^=0xff;failure([&]{bind_policy_payload_layout(p,reference,target_btf);});}
    {auto p=original;p.image[p.exports.at("maplesu_policy_layout")+24]^=8;failure([&]{bind_policy_payload_layout(p,reference,target_btf);});}
    {auto p=original;for(auto& s:p.segments)s.flags&=~2U;failure([&]{bind_policy_payload_layout(p,reference,target_btf);});}
    {auto p=original;p.relocations.push_back({p.exports.at("maplesu_policy_layout"),1027,0,{}});failure([&]{bind_policy_payload_layout(p,reference,target_btf);});}
    {auto bad=target;for(auto& t:bad)if(t.name=="cred")for(auto& f:t.fields)if(f.name=="uid")f.bit_size=64;
     const auto data=btf(bad);failure([&]{auto p=original;bind_policy_payload_layout(p,reference,data);});}
    {auto bad=target;for(auto& t:bad)if(t.name=="cred")for(auto& f:t.fields)if(f.name=="security")f.bit_offset+=8;
     const auto data=btf(bad);failure([&]{auto p=original;bind_policy_payload_layout(p,reference,data);});}
    {auto bad=target;for(auto& t:bad)if(t.name=="sk_buff")for(auto& f:t.fields)if(f.name=="cb")f.bit_size=8;
     const auto data=btf(bad);failure([&]{auto p=original;bind_policy_payload_layout(p,reference,data);});}
    for(const auto& slot:slots)if(slot.embedded){
        if(!table(baseline).alignments[&slot-slots])continue;
        auto bad=target;for(auto& t:bad)if(t.name==alias(slot.type,bad))for(auto& f:t.fields)if(f.name==slot.member)f.bit_size=8;
        const auto data=btf(bad);failure([&]{auto p=original;bind_policy_payload_layout(p,reference,data);});
    }
    {auto p=dynamic;failure([&]{bind_policy_payload_layout(p,reference,target_btf);});}
    if(argc==3){std::ifstream kernel_btf(argv[2],std::ios::binary);assert(kernel_btf);std::vector<uint8_t> data((std::istreambuf_iterator<char>(kernel_btf)),{});
        auto p=original;assert(bind_policy_payload_layout(p,reference,data));check_bound(table(p),reference);exercise_access(table(p));}
    printf("PASS %u dynamic native-layout cases (actual PIC slots, moved fields, enlarged allocations, production UID/SID/parent/context accessors, install ordering and malformed metadata; kernel I/O fixture)\n",cases);
}
