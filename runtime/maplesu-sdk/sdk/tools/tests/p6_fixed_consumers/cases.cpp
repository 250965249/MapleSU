#undef printf
#undef puts
static unsigned checks=0,failures=0;
static void check(bool pass,const char* label) {++checks;if(!pass){++failures;std::fprintf(stderr,"FAIL %s\n",label);}}
#define CHECK(x) check((x),#x)
static bool selectors(std::initializer_list<uint32_t> expected) {
    if(fixture.requests.size()!=expected.size())return false;
    size_t i=0;for(auto op:expected)if(fixture.requests[i++].operation!=op)return false;
    return true;
}
static const std::vector<std::string> names={"ABCDEFGHIJKLMNO1","ABCDEFGHIJKLMNO1A"};
int main() {
    using kernel_module::RequestEarlyFixedResult;
    reset();fixture.fail_operation=1;fixture.business_code=-19909;fixture.native_errno=EIO;
    fixture.transport=KModErr::ERR_MODULE_TEST_CHANNEL;
    RequestEarlyFixedResult r;
    CHECK(kernel_module::maplesu_request_helper_fixed_business(1,0,0,0,r)==static_cast<KModErr>(-19909));
    CHECK(errno==EIO && r.effects==1);
    reset();fixture.fail_operation=1;fixture.transport=KModErr::ERR_MODULE_ROOT_KEY;fixture.transport_errno=ESTALE;
    CHECK(kernel_module::maplesu_request_helper_fixed_business(1,0,0,0,r)==KModErr::ERR_MODULE_ROOT_KEY);
    CHECK(errno==ESTALE);
    reset();fixture.fail_operation=1;fixture.native_errno=EIO;
    CHECK(kernel_module::maplesu_request_helper_fixed_business(1,0,0,0,r)==KModErr::ERR_MODULE_TEST_CHANNEL);
    CHECK(errno==EIO);

    for (const auto init : {mtk::init,inte::init}) {
        reset();CHECK(init()==KModErr::OK);CHECK(fixture.legacy_calls==0 && fixture.requests.size()==1);
        const auto op=init==mtk::init?1u:3u;
        CHECK(selectors({op}));
        reset();fixture.fail_operation=op;fixture.business_code=static_cast<int64_t>(KModErr::ERR_MODULE_SYMBOL_PARAM);
        fixture.native_errno=EFAULT;fixture.transport=KModErr::ERR_MODULE_TEST_CHANNEL;
        CHECK(init()==KModErr::ERR_MODULE_SYMBOL_PARAM);CHECK(errno==EFAULT && fixture.legacy_calls==0);
        reset();fixture.helper=false;CHECK(init()==KModErr::ERR_MODULE_READ_FILE);
        CHECK(fixture.legacy_calls==1 && fixture.requests.empty());CHECK(errno==EIO);
    }
    reset();CHECK(guard::init()==KModErr::OK);CHECK(selectors({2}));
    CHECK(fixture.legacy_calls==0 && fixture.work_calls==2 && fixture.work_value);
    reset();fixture.target_count=0;CHECK(guard::init()==KModErr::OK);
    CHECK(selectors({2}) && fixture.work_calls==1 && !fixture.work_value);
    reset();fixture.fail_operation=2;fixture.business_code=static_cast<int64_t>(KModErr::ERR_MODULE_NOT_KADDR);
    fixture.native_errno=EIO;fixture.transport=KModErr::ERR_MODULE_TEST_CHANNEL;
    CHECK(guard::init()==KModErr::ERR_MODULE_NOT_KADDR);CHECK(errno==EIO && fixture.work_calls==1 && fixture.legacy_calls==0);
    reset();fixture.work_error=KModErr::ERR_MODULE_WRITE_FILE;
    CHECK(guard::init()==KModErr::ERR_MODULE_WRITE_FILE);CHECK(errno==EACCES && fixture.requests.empty());
    reset();fixture.fail_work_enable=true;
    CHECK(guard::init()==KModErr::ERR_MODULE_WRITE_FILE);CHECK(errno==EIO && fixture.work_calls==2 && fixture.requests.size()==1);
    reset();std::ofstream("/work/remove-mode")<<"1";CHECK(guard::init()==KModErr::OK);
    CHECK(fixture.remove_calls==3 && fixture.requests.empty() && fixture.work_calls==1);
    reset();fixture.helper=false;CHECK(guard::init()==KModErr::ERR_MODULE_READ_FILE);
    CHECK(fixture.legacy_calls==1 && fixture.requests.empty());

    reset();CHECK(root_consumer::init_anti_detect_root_env(names,false)==KModErr::OK);
    CHECK(selectors({4}) && fixture.requests[0].value==0 && fixture.legacy_calls==0 && fixture.roots==1);
    reset();CHECK(root_consumer::init_anti_detect_root_env({},true)==KModErr::OK);
    CHECK(selectors({4}) && fixture.requests[0].value==1 && fixture.legacy_calls==0);
    reset();fixture.root_error=KModErr::ERR_MODULE_ROOT_KEY;
    CHECK(root_consumer::init_anti_detect_root_env(names,false)==KModErr::ERR_MODULE_ROOT_KEY);
    CHECK(fixture.requests.empty() && fixture.legacy_calls==0);
    reset();fixture.storage_error=KModErr::ERR_MODULE_STORAGE_READ;
    CHECK(root_consumer::init_anti_detect_root_env(names,false)==KModErr::ERR_MODULE_STORAGE_READ);
    CHECK(fixture.requests.empty());
    for(const auto& bad : std::vector<std::vector<std::string>>{{},{"foreign"},{names[1],names[0]},{names[0],names[1],"extra"}}) {
        reset();CHECK(root_consumer::init_anti_detect_root_env(bad,false)==KModErr::ERR_MODULE_PARAM);
        CHECK(errno==EINVAL && fixture.requests.empty() && fixture.legacy_calls==0);
    }
    reset();fixture.fail_operation=4;fixture.business_code=-20019;fixture.native_errno=ENOSPC;
    fixture.transport=KModErr::ERR_MODULE_TEST_CHANNEL;
    CHECK(root_consumer::init_anti_detect_root_env(names,false)==static_cast<KModErr>(-20019));
    CHECK(errno==ENOSPC && fixture.legacy_calls==0);
    reset();fixture.helper=false;CHECK(root_consumer::init_anti_detect_root_env(names,false)==KModErr::ERR_MODULE_READ_FILE);
    CHECK(fixture.requests.empty() && fixture.legacy_calls==1);

    reset();selinux_kernel_status status{2,3,4,5,6};
    CHECK(selinux_consumer::read_selinux_kernel_status(status)==KModErr::OK);
    CHECK(status.version==1 && status.sequence==9 && status.enforcing==1 && status.policyload==1 && !status.deny_unknown);
    CHECK(fixture.legacy_calls==0 && selectors({7}));
    for(int malformed=0;malformed<3;++malformed) {
        reset();status={2,3,4,5,6};
        if(!malformed)fixture.status.version=2;
        else if(malformed==1)fixture.status.enforcing=2;
        else fixture.status.deny_unknown=2;
        CHECK(selinux_consumer::read_selinux_kernel_status(status)==KModErr::ERR_MODULE_TEST_CHANNEL);
        CHECK(errno==EPROTO && status.sequence==3 && status.version==2);
    }
    reset();status={2,3,4,5,6};fixture.fail_operation=7;fixture.business_code=-19909;fixture.native_errno=ENODEV;
    fixture.transport=KModErr::ERR_MODULE_TEST_CHANNEL;
    CHECK(selinux_consumer::read_selinux_kernel_status(status)==static_cast<KModErr>(-19909));
    CHECK(errno==ENODEV && status.sequence==3);
    reset();CHECK(selinux_consumer::write_selinux_kernel_status_sequence(0x12345678)==KModErr::OK);
    CHECK(selectors({8}) && fixture.requests[0].value==0x12345678 && fixture.legacy_calls==0);
    reset();SelinuxHookSwitch sw;sw.fixed=true;
    CHECK(selinux_consumer::enable_selinux_status_hooks(sw)==KModErr::OK);
    CHECK(selectors({6}) && !fixture.legacy_store);
    reset();sw={};sw.address=kKernelAddressFloor;sw.shared={1,kKernelAddressFloor};
    CHECK(selinux_consumer::enable_selinux_status_hooks(sw)==KModErr::OK);
    CHECK(fixture.requests.empty() && fixture.legacy_store==1);

    using maplesu::sdk::InstallMode;
    using maplesu::sdk::ExploitMethod;
    reset();CHECK(selinux_consumer::init(InstallMode::HotLoad,ExploitMethod::None)==KModErr::OK);
    CHECK(selectors({5,6,7,8,7,6}));
    CHECK(fixture.requests[0].mode==1 && fixture.requests[0].exploit==0 && fixture.status.sequence==4);
    CHECK(fixture.adbd==1 && fixture.legacy_calls==0 && fixture.properties==0 && fixture.enforcement==0);
    CHECK((fixture.events==std::vector<std::string>{"fixed-5","fixed-6","adbd","fixed-7","fixed-8","fixed-7","fixed-6"}));
    reset();fixture.enforcing=0;fixture.status.enforcing=0;fixture.boot_selinux="permissive";
    CHECK(selinux_consumer::init(InstallMode::Boot,ExploitMethod::None)==KModErr::OK);
    CHECK(fixture.properties==1 && fixture.enforcement==1 && fixture.adbd==1 && fixture.legacy_calls==0);
    CHECK(fixture.events[2]=="properties" && fixture.events[3]=="enforcing");
    reset();fixture.fail_operation=5;fixture.business_code=-19909;fixture.native_errno=ENOMEM;
    fixture.transport=KModErr::ERR_MODULE_TEST_CHANNEL;
    CHECK(selinux_consumer::init(InstallMode::Boot,ExploitMethod::None)==static_cast<KModErr>(-19909));
    CHECK(selectors({5}) && fixture.adbd==0 && fixture.legacy_calls==0);CHECK(errno==ENOMEM);
    reset();fixture.fail_operation=7;fixture.business_code=-20013;fixture.native_errno=EIO;
    fixture.transport=KModErr::ERR_MODULE_TEST_CHANNEL;
    CHECK(selinux_consumer::init(InstallMode::Boot,ExploitMethod::None)==static_cast<KModErr>(-20013));
    CHECK(selectors({5,6,7}) && fixture.adbd==1 && fixture.legacy_calls==0);CHECK(errno==EIO);
    reset();fixture.status.sequence=0;fixture.status.policyload=2;
    CHECK(selinux_consumer::init(InstallMode::Boot,ExploitMethod::CVE2026_43499)==KModErr::OK);
    CHECK(selectors({5,6,7,7,6}) && fixture.status.sequence==0 && fixture.requests[0].exploit==2);
    reset();fixture.helper=false;fixture.legacy_error=KModErr::ERR_MODULE_STORAGE_READ;
    CHECK(selinux_consumer::init(InstallMode::Boot,ExploitMethod::None)==KModErr::ERR_MODULE_STORAGE_READ);
    CHECK(fixture.requests.empty() && fixture.legacy_calls==1);
    std::fprintf(stdout,"fixed consumers checks=%u failures=%u\n",checks,failures);
    return failures?1:0;
}
