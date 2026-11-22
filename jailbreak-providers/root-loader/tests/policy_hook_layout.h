/* Host fixture layout for policy_hook_transport_test.c; never a device ABI. */
#define MSU_PH_PAGE_BYTES 4096
#define MSU_PH_KPROBE_SIZE 128
#define MSU_PH_KP_ADDR 40
#define MSU_PH_KP_NAME 48
#define MSU_PH_KP_PRE 64
#define MSU_PH_REGS_PC 256
#define MSU_PH_PROC_OPS_SIZE 104
#define MSU_PH_PROC_IOCTL 48
#define MSU_PH_EXECMEM_MODULE_TEXT 0
#define MSU_PH_ALLOWED_SYMBOLS "set_memory_nx","set_memory_rw","set_memory_ro","set_memory_x","sel_write_context","sel_write_access","selinux_setprocattr","sel_open_handle_status","sel_read_handle_status","sel_mmap_handle_status","sk_filter_trim_cap","commit_creds","__skb_try_recv_datagram","copy_process","selnl_notify_policyload","sel_write_load","ksys_write"
