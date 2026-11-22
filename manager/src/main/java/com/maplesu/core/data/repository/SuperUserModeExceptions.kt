package com.maplesu.core.data.repository

/**
 * 未判定态：超管页只读空态 + 明确错误，**不发起任何 root**（主文档 §3.3 / 01 §1.2）。
 */
class SuperUserModeUnresolvedException :
    IllegalStateException("MODE_UNRESOLVED: superuser backend is blocked until the work mode is determined")

/** KSU 模式但 KSU 授权后端不可用（未认主/原生库缺失）：显式不可用，绝不回退 Lite。 */
class SuperUserKsuBackendUnavailableException :
    IllegalStateException("KSU_SUPERUSER_UNAVAILABLE: the KSU superuser backend is not available")
