#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "environment_backend_identity.h"
int maplesu_environment_policy_load(const char*);
static void directory(const char* path) { if(mkdir(path, 0700) && errno != EEXIST) exit(100); }
int main(int argc, char** argv) {
    if(argc != 2) return 101;
    directory("/tmp/helper-policy"); directory("/tmp/helper-policy/adb");
    directory("/tmp/helper-policy/adb/maplesu"); directory("/tmp/helper-policy/adb/maplesu/bin");
    char target[512];
    snprintf(target,sizeof(target),"/tmp/helper-policy/adb/maplesu/bin/%s",MAPLESU_POLICY_BACKEND_FILE);
    int input = open("/work/loader-backend.so",O_RDONLY), output=open(target,O_CREAT|O_WRONLY,0700);
    if(input<0 || output<0) return 102;
    char bytes[4096]; ssize_t count;
    while((count=read(input,bytes,sizeof(bytes)))>0) if(write(output,bytes,count)!=count) return 103;
    close(input);close(output);
    if(!strcmp(argv[1],"missing")) unlink(target);
    else if(!strcmp(argv[1],"size")) { if(truncate(target,1)) return 105; }
    else if(!strcmp(argv[1],"note")) { output=open(target,O_WRONLY); unsigned char changed=maplesu_policy_backend_note[16]^0xff; if(output<0 || pwrite(output,&changed,1,MAPLESU_POLICY_BACKEND_NOTE_OFFSET+16)!=1) return 106; close(output); }
    int result=maplesu_environment_policy_load("fixture-key");
    int constructor=access("/tmp/loader-constructor",F_OK)==0;
    int entry=access("/tmp/loader-entry",F_OK)==0;
    int valid=!strcmp(argv[1],"valid");
    int expected=valid?0:(!strcmp(argv[1],"missing")?2:7);
    if(result!=expected || constructor!=valid || entry!=valid) {
        fprintf(stderr,"FAIL paired loader %s rc=%d expected=%d constructor=%d entry=%d\n",argv[1],result,expected,constructor,entry);
        return 104;
    }
    printf("PASS paired loader %s rc=%d constructor=%d entry=%d\n",argv[1],result,constructor,entry);
    return 0;
}
