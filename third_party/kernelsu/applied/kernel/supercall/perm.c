#include <linux/types.h>

#include "supercall/internal.h"
#include "manager/manager_identity.h"
#include "manager/app_lock.h"
#include "policy/allowlist.h"

bool only_manager(void)
{
    return is_manager();
}

bool only_root(void)
{
    return current_uid().val == 0;
}

bool manager_or_root(void)
{
    return current_uid().val == 0 || is_manager();
}

bool always_allow(void)
{
    return true;
}

bool allowed_for_su(void)
{
    return is_manager() || ksu_is_allow_uid_for_current(current_uid().val);
}

/*
 * MapleSU 分支：断代闸门的安全阀权限（03 分册 §2.3 / §9-R2）。
 *
 * ⚠️ 7K v2.30 的实现还放行「任意用我方证书签名、但没被认主的 APK」
 *    （ksu_is_signed_manager_uid）。那条链路需要 manager 侧 signed-appid 记录
 *    （7K 的 note_signed_manager / ksu_set_signed_manager_appid），且属产品决策 R2；
 *    0005 只落地「证书 + 世代」闸门，不落地 signed-manager 记录。
 *    v1 因此采用保守形态：root 或**已认主**的管理器。
 * TODO(R2): 若产品决定「签名即可关隐身」，在 0005 补齐 note_signed_manager 后放宽。
 */
bool stealth_valve_allowed(void)
{
    return current_uid().val == 0 || is_manager();
}

/*
 * ── App lock 权限形态（03 分册 §2.3）────────────────────────────────────
 * 因为 ksu_app_lock_ok() 恒为 true，*_authed 变体**当前等价**于原函数：
 *   only_manager_authed  == only_manager
 *   manager_or_root_authed == manager_or_root
 *   allowed_for_su_authed  == allowed_for_su
 * 这条等价关系必须钉死：未来若真实现 app lock，授权语义变化必须显式 review，
 * 不允许「顺手」改变 GRANT_ROOT / SET_APP_PROFILE / SET_FEATURE 的权限面。
 */
bool only_manager_authed(void)
{
    return is_manager() && ksu_app_lock_ok();
}

bool manager_or_root_authed(void)
{
    return current_uid().val == 0 || only_manager_authed();
}

bool allowed_for_su_authed(void)
{
    if (current_uid().val == 0) {
        return true;
    }

    if (ksu_is_allow_uid_for_current(current_uid().val)) {
        return true;
    }

    return only_manager_authed();
}
