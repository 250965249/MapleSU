# GhostSam fork 测试签名（TEST-ONLY / 公开测试用途）

> **本目录是公开测试签名材料，仅用于 fork 自建 CI 联调与本地验证。**
> **正式分发 / 面向任何最终用户之前，必须替换为私有签名，绝不可用本测试密钥签名对外发布。**

主人无法提供官方签名的 Manager APK / 证书，故由 fork 自行编译并签名：本地用 JDK21 `keytool` 生成一把**公开的测试密钥**，Manager APK、内核期望指纹（KSU_EXPECTED_*）、ksud-maplesu 三件产物统一指向这把测试证书，使 CI 可一体化产出并保持指纹一致。

## 文件

| 文件 | 说明 |
|---|---|
| `ghostsam-test.keystore` | PKCS12 密钥库，含测试私钥（alias `ghostsam-test`，2048-bit RSA）。**公开测试材料**，无任何保密性。 |
| `ghostsam-test.cer` | 由上述密钥库导出的 DER 编码 X.509 证书（公开证书，911 字节）。 |

## 指纹（供 t39 同步 GhostSam 侧 pin）

| 项 | 值 |
|---|---|
| Alias | `ghostsam-test` |
| 条目类型 | `PrivateKeyEntry` |
| 密钥算法 / 长度 | RSA / 2048-bit |
| 证书主体 | `CN=GhostSam-Test, OU=GhostSam-Test, O=GhostSam-Test, L=Test, ST=Test, C=US` |
| 有效期 | 2026-11-26 → 2054-04-13（约 10000 天） |
| **DER 字节数** | **911** |
| **证书 SHA-256** | **`cd0c477bcacc58c694367cb9a2f696d3bfd5de3e0ee8a0e25451cecbf312db90`** |
| 证书 SHA-256 指纹（keytool） | `CD:0C:47:7B:CA:CC:58:C6:94:36:7C:B9:A2:F6:96:D3:BF:D5:DE:3E:0E:E8:A0:E2:54:51:CE:CB:F3:12:DB:90` |
| 证书自身签名算法 | SHA384withRSA |

> `KSU_EXPECTED_SIZE` = DER 字节数 = **911**；`KSU_EXPECTED_HASH` = `sha256(cert.der)` = **`cd0c477b…db90`**。keytool 的 SHA256 指纹与 `sha256sum ghostsam-test.cer` 一致（仅大小写/冒号差异）。

## 测试口令（TEST-ONLY，故意公开）

- store password：`GhostSamTest2026`
- key password：`GhostSamTest2026`

因为密钥库本身是**公开测试材料**，口令不构成任何秘密；CI workflow 与 t39 均使用该固定值。正式签发必须换成私有密钥库 + 私有口令（走 Actions Secrets，参见 `.github/workflows/build-manager.yml` 的 `KEYSTORE/KEYSTORE_PASSWORD/KEY_ALIAS/KEY_PASSWORD` 模式）。

## 生成命令（可复现）

```bash
keytool -genkeypair -v \
  -keystore keystore/ghostsam-test.keystore -storetype PKCS12 \
  -alias ghostsam-test -keyalg RSA -keysize 2048 -validity 10000 \
  -storepass GhostSamTest2026 -keypass GhostSamTest2026 \
  -dname "CN=GhostSam-Test, OU=GhostSam-Test, O=GhostSam-Test, L=Test, ST=Test, C=US"
keytool -exportcert -alias ghostsam-test \
  -keystore keystore/ghostsam-test.keystore -storepass GhostSamTest2026 \
  -file keystore/ghostsam-test.cer
sha256sum keystore/ghostsam-test.cer   # = cd0c477b…db90
wc -c < keystore/ghostsam-test.cer     # = 911
```

## 更换 / 轮换流程

1. 删除 `keystore/ghostsam-test.keystore` 与 `keystore/ghostsam-test.cer`，或换用新 alias/口令，重新执行上面的 `keytool` 命令。
2. 重新计算新证书的 DER 字节数与 SHA-256。
3. 同步更新以下 pin（三件产物指纹须一致）：
   - `.github/workflows/ghostsam-build.yml` 的 `KSU_EXPECTED_SIZE` / `KSU_EXPECTED_HASH`（内核期望指纹，经 `build_lkm.sh` env 通道，不改 applied/manifest）。
   - GhostSam 侧 probe pin（属 t39）：`KernelSuProbe` / `KsudVariant.MAPLESU_CERT_SHA256`、`tools/verify_manager_apks.py` 的 `MANAGERS["maplesu"].certificate`、`tools/verify_manager_pairing.py` 期望值。
4. 更新本 README 的指纹表。

## 安全声明

- 本 keystore 的私钥与口令均为**公开测试值**，任何拿到本仓库的人都能用它签名 APK——这正是公开测试密钥的用途（CI 联调 / 指纹链路验证）。
- **不得**用它签名任何对外分发的产物；正式发布必须使用离线保管的私有密钥库，并通过 CI Secrets 注入。
- 详情见 `reports/maplesu/samsung-delta-implementation.md` 的「测试签名」章节。
