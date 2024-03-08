# arm_code_emulator
Simple ARM machine code disassembler and emulator

# Usage

```bash
$ python3 arm_emulator.py
   0:   e3010337        movw    r0, #4919       @ 0x1337
   4:   e30312ca        movw    r1, #13002      @ 0x32ca
   8:   e34c163c        movt    r1, #50748      @ 0xc63c
   c:   e30b2f73        movw    r2, #49011      @ 0xbf73
  10:   e34a2ac1        movt    r2, #43713      @ 0xaac1
  14:   e0200001        eor     r0, r0, r1
  18:   e0200002        eor     r0, r0, r2
  1c:   e30f157d        movw    r1, #62845      @ 0xf57d
  20:   e34b189f        movt    r1, #47263      @ 0xb89f
  24:   e30c2ceb        movw    r2, #52459      @ 0xcceb
  28:   e34d2eeb        movt    r2, #57067      @ 0xdeeb
  2c:   e0400001        sub     r0, r0, r1
  30:   e0c00002        sbc     r0, r0, r2
  34:   e3021208        movw    r1, #8712       @ 0x2208
  38:   e3441c67        movt    r1, #19559      @ 0x4c67
  3c:   e30d2f89        movw    r2, #57225      @ 0xdf89
  40:   e34e214c        movt    r2, #57676      @ 0xe14c
  44:   e0000001        and     r0, r0, r1
  48:   e0000002        and     r0, r0, r2
  4c:   e30c16ad        movw    r1, #50861      @ 0xc6ad
  50:   e342141b        movt    r1, #9243       @ 0x241b
  54:   e30a23fb        movw    r2, #41979      @ 0xa3fb
  58:   e34320f7        movt    r2, #12535      @ 0x30f7
  5c:   e2600000        rsb     r0, r0, #0
  60:   e30618e8        movw    r1, #26856      @ 0x68e8
  64:   e34f1628        movt    r1, #63016      @ 0xf628
  68:   e305282a        movw    r2, #22570      @ 0x582a
  6c:   e34527c1        movt    r2, #22465      @ 0x57c1
  70:   e2600000        rsb     r0, r0, #0
  74:   e3051ab7        movw    r1, #23223      @ 0x5ab7
  78:   e34a117c        movt    r1, #41340      @ 0xa17c
  7c:   e3082a1e        movw    r2, #35358      @ 0x8a1e
  80:   e3442f5d        movt    r2, #20317      @ 0x4f5d
  84:   e2600000        rsb     r0, r0, #0
  88:   e30e1a70        movw    r1, #60016      @ 0xea70
  8c:   e34f1d9d        movt    r1, #64925      @ 0xfd9d
  90:   e30320ca        movw    r2, #12490      @ 0x30ca
  94:   e3412105        movt    r2, #4357       @ 0x1105
  98:   e1800001        orr     r0, r0, r1
  9c:   e1800002        orr     r0, r0, r2
  a0:   e30117ba        movw    r1, #6074       @ 0x17ba
  a4:   e34317cc        movt    r1, #14284      @ 0x37cc
  a8:   e30e299e        movw    r2, #59806      @ 0xe99e
  ac:   e3432f98        movt    r2, #16280      @ 0x3f98
  b0:   e2600000        rsb     r0, r0, #0
  b4:   e3061631        movw    r1, #26161      @ 0x6631
  b8:   e3411d88        movt    r1, #7560       @ 0x1d88
  bc:   e30c21cf        movw    r2, #49615      @ 0xc1cf
  c0:   e3432d7a        movt    r2, #15738      @ 0x3d7a
  c4:   e2600000        rsb     r0, r0, #0
  c8:   e3011e11        movw    r1, #7697       @ 0x1e11
  cc:   e34f1d35        movt    r1, #64821      @ 0xfd35
  d0:   e30f2803        movw    r2, #63491      @ 0xf803
  d4:   e3402ed4        movt    r2, #3796       @ 0xed4
  d8:   e0000190        mul     r0, r0, r1
  dc:   e0000290        mul     r0, r0, r2
  e0:   e30f13ba        movw    r1, #62394      @ 0xf3ba
  e4:   e34f1fe4        movt    r1, #65508      @ 0xffe4
  e8:   e30a2e37        movw    r2, #44599      @ 0xae37
  ec:   e34425ec        movt    r2, #17900      @ 0x45ec
  f0:   e0000190        mul     r0, r0, r1
  f4:   e0000290        mul     r0, r0, r2
  f8:   e30e1e11        movw    r1, #60945      @ 0xee11
  fc:   e3451aa8        movt    r1, #23208      @ 0x5aa8
 100:   e30727b0        movw    r2, #30640      @ 0x77b0
 104:   e34a2157        movt    r2, #41303      @ 0xa157
 108:   e0200001        eor     r0, r0, r1
 10c:   e0200002        eor     r0, r0, r2
 110:   e30e1cfa        movw    r1, #60666      @ 0xecfa
 114:   e34e1695        movt    r1, #59029      @ 0xe695
 118:   e307270e        movw    r2, #30478      @ 0x770e
 11c:   e34d2187        movt    r2, #53639      @ 0xd187
 120:   e0000190        mul     r0, r0, r1
 124:   e0000290        mul     r0, r0, r2
 128:   e30d11fb        movw    r1, #53755      @ 0xd1fb
 12c:   e34e1484        movt    r1, #58500      @ 0xe484
 130:   e3042b03        movw    r2, #19203      @ 0x4b03
 134:   e3472364        movt    r2, #29540      @ 0x7364
 138:   e0000001        and     r0, r0, r1
 13c:   e0000002        and     r0, r0, r2
 140:   e3081a0e        movw    r1, #35342      @ 0x8a0e
 144:   e3431bb9        movt    r1, #15289      @ 0x3bb9
 148:   e30026aa        movw    r2, #1706       @ 0x6aa
 14c:   e34327ca        movt    r2, #14282      @ 0x37ca
 150:   e0400001        sub     r0, r0, r1
 154:   e0c00002        sbc     r0, r0, r2
 158:   e30f1a32        movw    r1, #64050      @ 0xfa32
 15c:   e34a1b6b        movt    r1, #43883      @ 0xab6b
 160:   e30f2552        movw    r2, #62802      @ 0xf552
 164:   e34726bc        movt    r2, #30396      @ 0x76bc
 168:   e0200001        eor     r0, r0, r1
 16c:   e0200002        eor     r0, r0, r2
 170:   e30a1ab9        movw    r1, #43705      @ 0xaab9
 174:   e3461bbc        movt    r1, #27580      @ 0x6bbc
 178:   e3092219        movw    r2, #37401      @ 0x9219
 17c:   e34524ec        movt    r2, #21740      @ 0x54ec
 180:   e2600000        rsb     r0, r0, #0
 184:   e302119e        movw    r1, #8606       @ 0x219e
 188:   e3431ad1        movt    r1, #15057      @ 0x3ad1
 18c:   e30826be        movw    r2, #34494      @ 0x86be
 190:   e3422ec5        movt    r2, #11973      @ 0x2ec5
 194:   e2600000        rsb     r0, r0, #0
 198:   e30b11ab        movw    r1, #45483      @ 0xb1ab
 19c:   e34d1091        movt    r1, #53393      @ 0xd091
 1a0:   e3002b78        movw    r2, #2936       @ 0xb78
 1a4:   e344236c        movt    r2, #17260      @ 0x436c
 1a8:   e2600000        rsb     r0, r0, #0
 1ac:   e30c1036        movw    r1, #49206      @ 0xc036
 1b0:   e34411a9        movt    r1, #16809      @ 0x41a9
 1b4:   e3042a6e        movw    r2, #19054      @ 0x4a6e
 1b8:   e34127cc        movt    r2, #6092       @ 0x17cc
 1bc:   e0800001        add     r0, r0, r1
 1c0:   e0a00002        adc     r0, r0, r2 

Emulated result of R0: 0x81e6a7d (136211069)
Emulated result of R1: 0x41a9c036 (1101643830)
Emulated result of R2: 0x17cc4a6e (399264366)
```
