#ifndef __KSU_H_APK_V2_SIGN
#define __KSU_H_APK_V2_SIGN

#include <linux/types.h>

bool is_manager_apk(char *path);
/* MapleSU: 返回 -1=非我方签名 / 0=签名对但无世代标记 / >0=世代号 */
int ksu_manager_apk_gen(char *path);
int get_pkg_from_apk_dir_path(char *pkg, const char *path);
/* MapleSU W18b：从 base.apk 路径取包名（三重校验用，见 apk_sign.c） */
int get_pkg_from_apk_path(char *pkg, const char *path);

#endif
