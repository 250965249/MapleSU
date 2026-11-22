#include <algorithm>
#include "stat_uid_path.cpp"
#include <fstream>
std::string default_modules::module_su_redirect::PatchBase::get_fake_su_path(){return "/data/ABCDEFGHIJKLMNOPA/su";}
namespace kernel_module::string_ops {
 void kstrcpy(Assembler* a,GpX dst,GpX src){
  // Runtime fixture preserves every register except x0, as the SDK contract states.
  (void)dst;(void)src; a->brk(Imm(1));
 }
}
namespace kernel_module::export_symbol {
 void get_current(Assembler* a,GpX out){a->mov(out,Imm(0x30000));}
 void copy_to_user(Assembler* a,KModErr& error,GpX dst,GpX src,uint64_t size){
  (void)dst;(void)src;a->mov(x0,Imm(size));a->brk(Imm(2));error=KModErr::OK;
 }
}
int main(){
 int32_t object[10]={32,4,12};
 auto path=maplesu_stat_uid_template(object);
 if(path!="/data/ABCDEFGHIJKLMNOPA/u-00000000/su")return 2;
 auto ctx=init_aarch64_asm();auto a=ctx.assembler();KModErr error=KModErr::OK;
 maplesu_emit_uid_stat_copy(a,error,x12,x10,path.size()+1,object);a->ret(x30);
 auto bytes=aarch64_asm_to_bytes(a);if(ctx.has_error()||bytes.empty())return 3;
 std::ofstream out("/out/stat-code.bin",std::ios::binary);out.write(reinterpret_cast<char*>(bytes.data()),bytes.size());
 std::ofstream str("/out/template.txt");str<<path;
 return 0;
}
