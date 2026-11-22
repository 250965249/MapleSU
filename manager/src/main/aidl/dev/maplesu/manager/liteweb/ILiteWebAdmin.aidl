package dev.maplesu.manager.liteweb;

import android.os.Bundle;

/**
 * H2：Lite 网页管理器的 root 进程控制面。
 *
 * 所有方法都由 root 进程内的 `LiteWebAdminService` 实现；调用者身份由
 * ManagerCallerVerifier 按 Binder UID 校验。token 只在内存/回执中出现，不落日志/prefs。
 */
interface ILiteWebAdmin {
    /** 生成/加载配置并开始监听；返回 {running, port, url, token?}。 */
    Bundle start();

    /** 停止监听并持久化 enabled=false。 */
    Bundle stop();

    Bundle status();

    /** 重新生成 token（原 URL 立即失效）并按原启用状态重启。 */
    Bundle resetToken();
}
