#include "module_err_def.h"
#include "maplesu_request_private.h"
#include "../maplesu-sdk/sdk/src/payload/su/su_session_receipt.h"
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
static int mode=0,calls=0,consumes=0,closes=0,raw=0;
static uid_t uid=10498;
static const char key[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv";
extern "C" uid_t __wrap_getuid(){return uid;}
extern "C" uid_t __wrap_geteuid(){return uid;}
extern "C" int __wrap_getresuid(uid_t*a,uid_t*b,uid_t*c){*a=*b=*c=uid;return 0;}
extern "C" int __wrap_getresgid(gid_t*a,gid_t*b,gid_t*c){*a=*b=*c=uid;return 0;}
extern "C" DIR* __wrap_opendir(const char*){if(mode==7){errno=EACCES;return nullptr;}return reinterpret_cast<DIR*>(1);}
extern "C" int __wrap_dirfd(DIR*){return 42;}
extern "C" int __wrap_closedir(DIR*){return 0;}
extern "C" dirent* __wrap_readdir(DIR*){static dirent item{};static bool done=false;if(done || mode<8){errno=0;return nullptr;}done=true;strcpy(item.d_name,"99");return &item;}
extern "C" ssize_t __wrap_readlinkat(int,const char*,char*out,size_t max){const char name[]="anon_inode:[" MSU_SU_SESSION_NAME "]";const auto count=sizeof(name)-1;if(count>max)abort();memcpy(out,name,count);return count;}
extern "C" int __real_close(int);
extern "C" int __wrap_close(int fd){if(fd==99){++closes;return 0;}return __real_close(fd);}
extern "C" int __wrap_fcntl(int,int command,...){return command==F_GETFD?0:0;}
extern "C" int __wrap_ioctl(int,unsigned long command,...){++consumes;if(mode==9){errno=EINTR;return -1;}va_list args;va_start(args,command);auto*out=va_arg(args,msu_su_session_receipt*);va_end(args);*out={};out->magic=MSU_SU_SESSION_MAGIC;out->version=MSU_SU_SESSION_VERSION;out->bytes=sizeof(*out);out->state=MSU_SU_SESSION_APPLIED|MSU_SU_SESSION_EXECUTED|MSU_SU_SESSION_CONSUMED;out->target_uid=uid;out->target_gid=uid;return 0;}
extern "C" long __wrap_syscall(long,...){++raw;errno=ENOENT;return -1;}
namespace default_modules::module_root { KModErr set_current_root_for_su(const char* got){++calls;if(strcmp(key,got))abort();if(mode==1){errno=EACCES;return KModErr::ERR_MODULE_NO_ROOT;}if(mode==2)return KModErr::ERR_MODULE_NO_ROOT;if(mode!=3)uid=0;return KModErr::OK;} }
namespace maplesu::payload::su { bool acquire_root(const char*); }
int main(int argc,char**argv){mode=argc>1?atoi(argv[1]):0;if(mode==4)uid=0;if(mode>=8)uid=10777;errno=0;const bool ok=maplesu::payload::su::acquire_root(mode==5?nullptr:mode==6?"short":key);
 bool pass=false;
 switch(mode){case 0:pass=ok&&uid==0&&calls==1&&!raw;break;case 1:pass=!ok&&errno==EACCES&&calls==1&&!raw;break;case 2:case 3:pass=!ok&&errno==EPERM&&calls==1&&!raw;break;case 4:pass=ok&&!calls&&!raw;break;case 5:case 6:pass=!ok&&errno==EINVAL&&!calls&&!raw;break;case 7:pass=!ok&&errno==EACCES&&!calls&&!raw;break;case 8:pass=ok&&uid==10777&&consumes==1&&closes==1&&!calls&&!raw;break;case 9:pass=!ok&&errno==EINTR&&consumes==1&&closes==1&&!calls&&!raw;break;}
 printf("case=%d pass=%d ok=%d errno=%d sdkCalls=%d rawRequests=%d consumes=%d\n",mode,pass,ok,errno,calls,raw,consumes);return pass?0:1;
}
