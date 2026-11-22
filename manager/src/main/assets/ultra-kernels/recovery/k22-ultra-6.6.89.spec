#kernel=6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k
#key=8eORURvE0cAkp3mlIzCuUsEJrr4OfbjKfT6RvkjeIP6aKm6r
# ============================== k21 spec ====================================
# k21 = the two already validated debug variants merged into one kernel:
#   * k20 (boot 92834de76efbf3a671251356db27f66987338c7b11fe5f432a6ce2755bc7e13f,
#     DEVICE PROVEN: full boot with env installed, env init really ran)
#        0x8FCFD8  cmp w1,#0xa   ->  1f2003d5  nop
#        0x8FCFDC  b.hs 0x8FCFE4 ->  1f2003d5  nop
#   * k15 (boot 6a44a9f6f9299a37dca6ea6fd85be2ea6a37666aa5398c58b2b29e7335af307c,
#     BUILD PROVEN: 54 B envelope at 0x45590, byte-identical to this record)
#          0x45590  8 B append package -> 54 B envelope (self/kallsyms/path/
#                   do_exec/2x const/filldir64/seccomp offset 0x08E8)
# Base : k7-pkg45590-6.6.89.txt (4,289 B, sha256 693123bf712de662..., 16 records).
# Built on the pristine kernel inside magiskboot-reference/unchanged-repacked.img
#   @0x1000, 36,661,760 B, sha256 346d51ea1f63413ffa5d99c5c426806291af3573f0a1d66a7621c388e835880e.
#
# STATUS: candidate DEBUG image, NOT a delivery kernel.  NOP-ing the ssid gate
#         RELAXES SELinux (it drops the `source SID < 10` condition).  It exists
#         only to test whether init takes the normal exec path far enough to pass
#         gate13 set_current_root.  Final delivery needs a fix that does NOT
#         relax SELinux; that work item is tracked in 42-k21-build.md section 7.
#
# Record accounting (17 records, index 0..16):
#   index  0..14  byte-identical to k7's records 0..14 (same offset/orig/repl).
#   index 15      k15's record verbatim: offset 284048 = 0x45590, orig = the
#                 54 B pristine window, replacement = the 54 B envelope.
#   index 16      k20's record verbatim: offset 9424856 = 0x8FCFD8, orig = the
#                 8 B pristine window, replacement = 2x nop.
# applyraw writes in file order, so index 12 (the 108 B AVC cave, 0x8FCF7C) lands
# first and index 16 then overwrites its 8 B `cmp`/`b.hs` window LAST.
#
# Envelope layout, pkg = 0x45590 (54 B = 0x45590..0x455C5):
#   +0x00 u32 self                    0x00045590
#   +0x04 u32 kallsyms_lookup_name    0x001B6560
#   +0x08 28B init_path               "/data/8eORURvE0cAkp3ml/init\0"
#   +0x24 u32 do_execveat_common      0x003DF804
#   +0x28 u32 const                   0xE7280001  (semantics unknown, carried)
#   +0x2C u32 const                   0x000B0062  (semantics unknown, carried)
#   +0x30 u32 filldir64               0x003F052C
#   +0x34 i16 task_struct.seccomp     0x08E8
#
# Expected verifyraw numbers (same shape as k20, one more record):
#   on the pristine base (346d51ea...)          : 17/17 orig, 0/17 replacement
#   on the built product k21-kernel.bin          : 0/17 orig, 16/17 replacement
#     (index 12's 108 B blob is no longer intact because index 16 rewrote 8 of
#      its bytes last; replaying the declared override gives 17/17)
#
# Build (offline, no device):
#   UltraBootSpec verifyraw <this> srcboot-kernel.bin        # 17/17 orig
#   UltraBootSpec applyraw  <this> srcboot-kernel.bin k21-kernel.bin
#   UltraBootSpec rebuild   magiskboot-reference/unchanged-repacked.img \
#                         k21-kernel.bin k21-boot.img
# ============================================================================
# ---- k22 record: euid==0 gate at 0x8FCFB0 (9424816) ----
135876|3f2303d5ff4302d1fd7b05a9f85f06a9f65707a9f44f08a9fd430191084138d5f30300aa001701b000b00491081143f9f60302aaf50301aaa8831ff8eb154194f40300aa223302947da404942000805271a01b94081701b040aa009000ac3e91093141b9e10313aae20316aa23050011033101b9d4b8409420008052e10313aae20315aae30316aae4031f2a650180522503039428009052f603002a1f00086be0000054d7950594e00315aa58e0ff97a82244391f0d007221040054e0031f2a55a01b94e000805221008052c632029449330294|cbff81923f000beb42060054104138d5111244f92b0040f90c0000100d089cd24d20a0f28c010d8b0d0080d26e696d388f696d38df010f6b61040054ad050091bfc100f14bffff546c010d8b8e0140398f494039ef010e0b8f4900398c0500918e4940394effff356c094139604144f89fc50071800100549fc90071a00100549fcd0071a00100549fd1007180010054f17fbfa910000014c2390094f17fc1a8070000146e0d41390e000039046f23140000403902000014056e2314200a00f9040000142d1a40b94d0000350b3f241408010014
136088|084138d5081140b91f3d1872c10f0054|604d40b940000034b1390094efffff17
137140|3f2303d5fd7bbda9f50b00f9f44f02a9fd030091282044391f0d0072e80300aaa0000054e00308aae20305aab9feff9718000014|fd7bc1a8e61fc1a8e417c1a8e20fc1a8e007c1a810f80e143f2303d5e007bfa9e20fbfa9e417bfa9e61fbfa9fd7bbfa9b8feff17
232480|3f2303d5fd7bbea9f44f01a9fd03009168b1009069b1009053e5009073020091081d45f929c144f9d405019094020091c3ad00b0637439912801|c0035fd6248c030060651b002f646174612f38654f52555276453063416b70336d6c2f696e69740004f83d00010028e762000b002c053f00e808
2852092|3f2303d5fd7bbfa9|200080d2c0035fd6
3583624|3f2303d5ffc301d1|e0031f2ac0035fd6
4061188|3f2303d5|f207f117
6522328|c0035fd6|72120b14
9423536|3f2303d5fd7bbca9f85f01a9f65702a9f44f03a9fd030091150840f9b60a40f9160500b4b80e40f9b70640f9e00301aaf30301aaa39a1c94080317eb4a0200540900188b3f0117ebad0300540801008ba90240f91f0116eb|c0035fd6ecb9ff908cb13091eb33bea9e0030caae243009121008052cc9beb97e0000035e04300912699eb97eb3340a98d1540386d150038cdffff35eb33c2a83193dc171f2003d51f2003d51f2003d51f2003d51f2003d5
9423756|3f2303d5fd7bbda9f65701a9f44f02a9fd030091150840f9a80a40f9680600b4f30301aaf40300aa026500b042442291e0031faae1031faae30313aab41f1d94a90e40f9167c4093aa0640f92801168b1f010aeb49020054|c0035fd631420091eb47bfa9604144f8615140b9e007bfa96101dd97e007c1a80202dd97eb47c1a80c0000941f7508d59f3b03d5df3f03d540013fd60b000014e07fbfa91f2003d5e401dd97e07fc1a8a324e297f592dc17
9423844|29010aeb4b020054a10a40f93f0016eb|615140b96a4144f8ea07bfa9c0035fd6
9423860|e9010054aa0240f90a0100b44001098b026500b0|e007c1a8f5ffff171f2003d51f2003d51f2003d5
9424764|3f2303d5ffc301d1fd7b06a9fd830191e31300a9084138d5e9030091081143f9e51b01a929a10091e71300f9a8831ff8a8430091e8a702a9e8048012ffa303a9e8a30091a2a33ea9ff2003d5e00000b5006b00f000780691a36300d1e2031eaaab491d9409000014e80300aa|c0035fd62e003bd5ce4d50d3ce0900910024ce9a0020ce9a207a0bd59f3b03d50692dc170b4138d56c1144f98d1940b9cd010035eecf04b26c1944f99f010eeb200100542ecd8d522e8dae729f010e6bc10000546dd160398d0000353f28007142000054e0031f2ac0035fd6
9637816|3f2303d5fd7bbfa9fd030091e50302aae80300aae10000b5e06100d0004c1591e10308aae20305aaaa791c941500001409054039284440f920c10051480100b5284040f9080100b5289841f9c80000b543630090|c0035fd60cc260399fa5017121020054050000142f6170705f70726f63657373363400008affff10ec030baaef030aaaee154038ce0000348d154038ad000034bf010e6b4f118f9afaffff17ac2eff17ebc1db17
17101596|3f2303d5ff4303d1fd7b08a9f94b00f9f85f0aa9f6570ba9f44f0ca9fd03029169850090f30300aaa89500902ac942b9|38654f52555276453063416b70336d6c497a43755573454a7272344f66626a4b66543652766b6a65495036614b6d3672
284048|c0035fd64e81c210c0035fd60145d0b53f2303d5fd7bbda9f65701a9f44f02a9fd030091e81201d0160d40f9560200b4f30301aa5400|9055040060651b002f646174612f38654f52555276453063416b70336d6c2f696e69740004f83d00010028e762000b002c053f00e808
9424856|e2031eaaab491d94|1f2003d51f2003d5
9424816|e8a702a9|0c000014
