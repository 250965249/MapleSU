# 主机测试资源

`lenovo-avb-fixtures.zip` 包含合成 boot/init_boot/vbmeta 镜像与公开 AOSP AVB 测试密钥，用于验证签名、描述符保留、镜像尺寸及失败恢复。它不包含个人设备镜像或 MapleSU 发布凭据。

测试从 classpath 解包到临时目录。完整运行入口是根目录的 `python tools/check_host.py`，无需手机或网络。AOSP 测试密钥来源、实际文件摘要和 VioletToolBox 适配来源见 [AVB NOTICE](../../../../manager/src/main/assets/maplesu/avb/NOTICE)，实现说明见 [AVB 签名说明](../../../../docs/LENOVO_AVB_SIGNING.md)。
