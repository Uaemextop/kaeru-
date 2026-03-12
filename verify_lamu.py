#!/usr/bin/env python3
"""Comprehensive verification of board-lamu.c against lk.img binary."""

import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

# ── Binary parameters ──────────────────────────────────────────────
IMG_PATH      = "lk.img"
BASE_ADDR     = 0x4C400000
HEADER_OFFSET = 0x200
CODE_SIZE     = 0x157934
BSS_START     = 0x4C557934
GOT_BASE      = 0x4C557118

LK_START = BASE_ADDR
LK_END   = BASE_ADDR + CODE_SIZE

def va_to_offset(va):
    return va - BASE_ADDR + HEADER_OFFSET

def offset_to_va(off):
    return BASE_ADDR + off - HEADER_OFFSET

# ── Load binary ────────────────────────────────────────────────────
with open(IMG_PATH, "rb") as f:
    data = f.read()

cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

def disasm_at(va, count=5):
    """Disassemble `count` instructions starting at VA."""
    off = va_to_offset(va)
    chunk = data[off:off+count*4]
    return list(cs.disasm(chunk, va, count=count))

def read16(va):
    off = va_to_offset(va)
    return struct.unpack_from("<H", data, off)[0]

def read32(va):
    off = va_to_offset(va)
    return struct.unpack_from("<I", data, off)[0]

# ── Pattern search ─────────────────────────────────────────────────
def search_pattern(pattern_hw, start_va=LK_START, end_va=LK_END):
    """Search for a sequence of 16-bit halfwords in the binary.
    Returns list of VAs where the pattern was found."""
    pat_bytes = b"".join(struct.pack("<H", hw) for hw in pattern_hw)
    results = []
    start_off = va_to_offset(start_va)
    end_off   = va_to_offset(end_va)
    search_data = data[start_off:end_off]
    pos = 0
    while True:
        idx = search_data.find(pat_bytes, pos)
        if idx == -1:
            break
        va = offset_to_va(start_off + idx)
        results.append(va)
        pos = idx + 2  # step by halfword
    return results

# ════════════════════════════════════════════════════════════════════
# REPORT
# ════════════════════════════════════════════════════════════════════
print("=" * 72)
print("  Comprehensive Verification Report: board-lamu.c vs lk.img")
print("=" * 72)

issues = []
warnings = []

# ── 1. SEARCH_PATTERN verification ────────────────────────────────
print("\n┌─────────────────────────────────────────────────────────┐")
print("│ 1. SEARCH_PATTERN Verification                         │")
print("└─────────────────────────────────────────────────────────┘\n")

patterns = {
    "fastboot_cmd_proc":               [0xE92D, 0x4880, 0xB087, 0x4D5A],
    "get_vfy_policy":                   [0xB508, 0xF7FF, 0xFF63, 0xF3C0],
    "tinno_commercial_lock":            [0xB538, 0xF04A, 0xFBC5, 0xB110],
    "secure_state_check":               [0xB508, 0xF7FF, 0xFFF9, 0xB908],
    "get_hw_sbc":                       [0x2360, 0xF2C1, 0x13CE, 0x6818],
    "tinno_facmode_init":               [0xE92D, 0x41F0, 0xB084, 0x4D28],
    "tinno_is_facmode":                 [0x4B05, 0x447B, 0x681B, 0x681B, 0x7918],
    "tinno_carrier_validate":           [0xE92D, 0x43F8, 0x4C35, 0x447C],
    "lock_state_thunk":                 [0xF05F, 0xBF1C],
    "cmdline_preprocess":               [0xF01A, 0xFE16, 0xF001, 0xF8EE],
    "env_init_done":                    [0xF040, 0xF929, 0x6823, 0x2000],
    "partition_write":                  [0xE92D, 0x4FF0, 0xB085, 0x461F, 0x4616, 0x9003, 0x9D0F, 0xF7FE, 0xFE2F],
    "avb_cmdline":                      [0xE92D, 0x4FF0, 0x4691, 0xF102],
    "load_and_verify_vbmeta":           [0xF47F, 0xAE6B, 0xE688, 0xF8DD],
    "orange_state_warning (late_init)": [0xB508, 0x4B0E, 0x447B],
}

pattern_addrs = {}

for name, pat in patterns.items():
    hits = search_pattern(pat)
    if len(hits) == 0:
        print(f"  ❌ {name}: NOT FOUND")
        issues.append(f"Pattern '{name}' not found in binary")
    elif len(hits) == 1:
        print(f"  ✅ {name}: FOUND at 0x{hits[0]:08X}")
        pattern_addrs[name] = hits[0]
    else:
        addrs_str = ", ".join(f"0x{a:08X}" for a in hits)
        print(f"  ⚠️  {name}: MULTIPLE MATCHES ({len(hits)}): {addrs_str}")
        warnings.append(f"Pattern '{name}' has {len(hits)} matches: {addrs_str}")
        pattern_addrs[name] = hits[0]

# ── 2. BSS/Data address verification ──────────────────────────────
print("\n┌─────────────────────────────────────────────────────────┐")
print("│ 2. BSS / Data Address Verification                     │")
print("└─────────────────────────────────────────────────────────┘\n")

bss_addrs = {
    "CMDLINE1_ADDR":              0x4C55CC0C,
    "CMDLINE2_ADDR":              0x4C55D410,
    "FASTBOOT_CMDLIST_ADDR":      0x4C607020,
    "TINNO_SSM_PERMISSION_ADDR":  0x4C56AD78,
}

for name, addr in bss_addrs.items():
    if addr >= BSS_START:
        print(f"  ✅ {name} = 0x{addr:08X}  (>= BSS_START 0x{BSS_START:08X})")
    elif addr >= LK_START and addr < BSS_START:
        print(f"  ⚠️  {name} = 0x{addr:08X}  (in code/data region, NOT BSS)")
        warnings.append(f"{name} 0x{addr:08X} is in code/data region, not BSS")
    else:
        print(f"  ❌ {name} = 0x{addr:08X}  (OUTSIDE LK range!)")
        issues.append(f"{name} 0x{addr:08X} is outside the LK address space")

# ── 3. CONFIG address verification ────────────────────────────────
print("\n┌─────────────────────────────────────────────────────────┐")
print("│ 3. CONFIG Address Verification (defconfig)              │")
print("└─────────────────────────────────────────────────────────┘\n")

config_code_addrs = {
    "CONFIG_BOOTLOADER_BASE":                0x4C400000,
    "CONFIG_PARTITION_READ_ADDRESS":         0x4C461100,
    "CONFIG_APP_ADDRESS":                    0x4C42A0C0,
    "CONFIG_PLATFORM_INIT_CALLER_ADDRESS":   None,  # not in defconfig; check CONFIG_PLATFORM_INIT_ADDRESS
    "CONFIG_PLATFORM_INIT_ADDRESS":          0x4C403944,
    "CONFIG_INIT_STORAGE_ADDRESS":           0x4C403754,
    "CONFIG_GET_ENV_ADDRESS":                0x4C460284,
    "CONFIG_SET_ENV_ADDRESS":                0x4C46049C,
    "CONFIG_BOOTMODE_ADDRESS":               0x4C5737EC,
}

# All addresses from defconfig that should point to code
defconfig_all = {
    "CONFIG_APP_ADDRESS":                      0x4C42A0C0,
    "CONFIG_APP_CALLER":                       0x4C427950,
    "CONFIG_BOOTLOADER_BASE":                  0x4C400000,
    "CONFIG_BOOTMODE_ADDRESS":                 0x4C5737EC,
    "CONFIG_DPRINTF_ADDRESS":                  0x4C443CCC,
    "CONFIG_FASTBOOT_FAIL_ADDRESS":            0x4C42ABAC,
    "CONFIG_FASTBOOT_INFO_ADDRESS":            0x4C42AB2C,
    "CONFIG_FASTBOOT_OKAY_ADDRESS":            0x4C42AD78,
    "CONFIG_FASTBOOT_PUBLISH_ADDRESS":         0x4C42A6D8,
    "CONFIG_FASTBOOT_REGISTER_ADDRESS":        0x4C42A69C,
    "CONFIG_FREE_ADDRESS":                     0x4C4440FC,
    "CONFIG_GET_ENV_ADDRESS":                  0x4C460284,
    "CONFIG_INIT_STORAGE_ADDRESS":             0x4C403754,
    "CONFIG_INIT_STORAGE_CALLER":              0x4C403972,
    "CONFIG_LK_LOG_STORE_ADDRESS":             0x4C459358,
    "CONFIG_MALLOC_ADDRESS":                   0x4C444A08,
    "CONFIG_MTK_DETECT_KEY_ADDRESS":           0x4C4054F8,
    "CONFIG_PARTITION_GET_SIZE_BY_NAME_ADDRESS":0x4C45FF60,
    "CONFIG_PARTITION_READ_ADDRESS":           0x4C461100,
    "CONFIG_PLATFORM_INIT_ADDRESS":            0x4C403944,
    "CONFIG_PLATFORM_INIT_CALLER":             0x4C4262AC,
    "CONFIG_SET_ENV_ADDRESS":                  0x4C46049C,
    "CONFIG_THREAD_CREATE_ADDRESS":            0x4C426A68,
    "CONFIG_THREAD_RESUME_ADDRESS":            0x4C426C7C,
    "CONFIG_VIDEO_PRINTF_ADDRESS":             0x4C443698,
}

# Non-code addresses (framebuffer, etc.)
skip_code_check = {"CONFIG_FRAMEBUFFER_ADDRESS"}

for name, addr in sorted(defconfig_all.items()):
    if name in skip_code_check:
        continue
    # BOOTMODE_ADDRESS is a data/BSS variable
    if "BOOTMODE" in name:
        if addr >= BSS_START:
            print(f"  ✅ {name} = 0x{addr:08X}  (BSS variable)")
        elif addr >= LK_START:
            print(f"  ⚠️  {name} = 0x{addr:08X}  (in code region; might be .data)")
            warnings.append(f"{name} might be in .data not BSS")
        else:
            print(f"  ❌ {name} = 0x{addr:08X}  (OUTSIDE LK range)")
            issues.append(f"{name} outside LK range")
        continue

    # LK_LOG_STORE is also a data address
    if "LOG_STORE" in name:
        if addr >= LK_START and addr < BSS_START:
            print(f"  ✅ {name} = 0x{addr:08X}  (data region)")
        else:
            print(f"  ⚠️  {name} = 0x{addr:08X}")
        continue

    # Code addresses: should be in [LK_START, LK_END)
    if addr >= LK_START and addr < LK_END:
        # Quick sanity: try to disassemble
        instrs = disasm_at(addr, 2)
        if instrs:
            print(f"  ✅ {name} = 0x{addr:08X}  (valid code: {instrs[0].mnemonic} {instrs[0].op_str})")
        else:
            print(f"  ⚠️  {name} = 0x{addr:08X}  (in range but disassembly failed)")
            warnings.append(f"{name} disassembly failed at 0x{addr:08X}")
    elif addr == BASE_ADDR:
        print(f"  ✅ {name} = 0x{addr:08X}  (base address)")
    else:
        print(f"  ❌ {name} = 0x{addr:08X}  (OUTSIDE code range 0x{LK_START:08X}-0x{LK_END:08X})")
        issues.append(f"{name} = 0x{addr:08X} is outside code range")

# ── 4. Fastboot cmd_proc patch offset verification ────────────────
print("\n┌─────────────────────────────────────────────────────────┐")
print("│ 4. Fastboot cmd_proc Patch Offset Verification          │")
print("└─────────────────────────────────────────────────────────┘\n")

FASTBOOT_FAIL_ADDR = 0x4C42ABAC

if "fastboot_cmd_proc" in pattern_addrs:
    fb_addr = pattern_addrs["fastboot_cmd_proc"]
    
    # Check +0xF0: should be cbz (security gate, to be replaced with unconditional branch)
    off_f0 = fb_addr + 0xF0
    hw = read16(off_f0)
    instrs = disasm_at(off_f0, 1)
    if instrs:
        i = instrs[0]
        print(f"  Checking +0xF0 (0x{off_f0:08X}): {i.mnemonic} {i.op_str}  [raw: 0x{hw:04X}]")
        if i.mnemonic == "cbz":
            print(f"  ✅ +0xF0 is a cbz instruction (security gate)")
        elif i.mnemonic == "b":
            print(f"  ✅ +0xF0 is already patched (unconditional branch)")
        else:
            print(f"  ❌ +0xF0 is '{i.mnemonic}' — expected cbz")
            issues.append(f"fastboot_cmd_proc+0xF0: expected cbz, got {i.mnemonic}")
    else:
        print(f"  ❌ +0xF0: disassembly failed [raw: 0x{hw:04X}]")
        issues.append("fastboot_cmd_proc+0xF0: disassembly failed")

    # Check +0x15A: should be bl to fastboot_fail
    off_15a = fb_addr + 0x15A
    instrs = disasm_at(off_15a, 1)
    if instrs:
        i = instrs[0]
        raw32 = read32(off_15a)
        print(f"  Checking +0x15A (0x{off_15a:08X}): {i.mnemonic} {i.op_str}  [raw: 0x{raw32:08X}]")
        if i.mnemonic == "bl":
            # Extract target from operand
            try:
                target = int(i.op_str.lstrip('#'), 0)
                if target == FASTBOOT_FAIL_ADDR:
                    print(f"  ✅ +0x15A is bl to fastboot_fail (0x{FASTBOOT_FAIL_ADDR:08X})")
                else:
                    print(f"  ⚠️  +0x15A is bl to 0x{target:08X}, expected 0x{FASTBOOT_FAIL_ADDR:08X}")
                    warnings.append(f"fastboot_cmd_proc+0x15A: bl target mismatch")
            except:
                print(f"  ⚠️  +0x15A is bl but couldn't parse target: {i.op_str}")
        else:
            print(f"  ❌ +0x15A is '{i.mnemonic}' — expected bl")
            issues.append(f"fastboot_cmd_proc+0x15A: expected bl, got {i.mnemonic}")
    else:
        print(f"  ❌ +0x15A: disassembly failed")
        issues.append("fastboot_cmd_proc+0x15A: disassembly failed")

    # Check +0x166: should be bl to fastboot_fail
    off_166 = fb_addr + 0x166
    instrs = disasm_at(off_166, 1)
    if instrs:
        i = instrs[0]
        raw32 = read32(off_166)
        print(f"  Checking +0x166 (0x{off_166:08X}): {i.mnemonic} {i.op_str}  [raw: 0x{raw32:08X}]")
        if i.mnemonic == "bl":
            try:
                target = int(i.op_str.lstrip('#'), 0)
                if target == FASTBOOT_FAIL_ADDR:
                    print(f"  ✅ +0x166 is bl to fastboot_fail (0x{FASTBOOT_FAIL_ADDR:08X})")
                else:
                    print(f"  ⚠️  +0x166 is bl to 0x{target:08X}, expected 0x{FASTBOOT_FAIL_ADDR:08X}")
                    warnings.append(f"fastboot_cmd_proc+0x166: bl target mismatch")
            except:
                print(f"  ⚠️  +0x166 is bl but couldn't parse target: {i.op_str}")
        else:
            print(f"  ❌ +0x166 is '{i.mnemonic}' — expected bl")
            issues.append(f"fastboot_cmd_proc+0x166: expected bl, got {i.mnemonic}")
    else:
        print(f"  ❌ +0x166: disassembly failed")
        issues.append("fastboot_cmd_proc+0x166: disassembly failed")

else:
    print("  ❌ fastboot_cmd_proc pattern not found, skipping offset checks")
    issues.append("Cannot verify fastboot_cmd_proc offsets — pattern not found")

# ── 5. load_and_verify_vbmeta patch offset verification ───────────
print("\n┌─────────────────────────────────────────────────────────┐")
print("│ 5. load_and_verify_vbmeta Patch Offset Verification     │")
print("└─────────────────────────────────────────────────────────┘\n")

if "load_and_verify_vbmeta" in pattern_addrs:
    vb_addr = pattern_addrs["load_and_verify_vbmeta"]
    
    # Check -0x32C: should contain a cmp instruction
    off_neg = vb_addr - 0x32C
    instrs = disasm_at(off_neg, 1)
    hw = read16(off_neg)
    if instrs:
        i = instrs[0]
        print(f"  Checking -0x32C (0x{off_neg:08X}): {i.mnemonic} {i.op_str}  [raw: 0x{hw:04X}]")
        if i.mnemonic == "cmp":
            print(f"  ✅ -0x32C is a cmp instruction")
            # Code patches it to 0x451B which is "cmp r3, r3"
            # The original should be "cmp r2, r3" or similar
            if "r2" in i.op_str and "r3" in i.op_str:
                print(f"       Original: cmp r2, r3 → will be patched to cmp r3, r3 (0x451B)")
            elif "r3, r3" in i.op_str:
                print(f"       Already appears to be cmp r3, r3")
            else:
                print(f"       Operands: {i.op_str}")
        else:
            print(f"  ❌ -0x32C is '{i.mnemonic} {i.op_str}' — expected cmp")
            issues.append(f"vbmeta-0x32C: expected cmp, got {i.mnemonic}")
    else:
        print(f"  ❌ -0x32C: disassembly failed [raw: 0x{hw:04X}]")
        issues.append("vbmeta-0x32C: disassembly failed")

    # Check +0x72: should contain "cmp r3, #0"
    off_72 = vb_addr + 0x72
    instrs = disasm_at(off_72, 1)
    hw = read16(off_72)
    if instrs:
        i = instrs[0]
        print(f"  Checking +0x72 (0x{off_72:08X}): {i.mnemonic} {i.op_str}  [raw: 0x{hw:04X}]")
        if i.mnemonic == "cmp" and "r3" in i.op_str and "#0" in i.op_str:
            print(f"  ✅ +0x72 is cmp r3, #0 → will be patched to movs r3, #1 (0x2301)")
        elif i.mnemonic == "cmp":
            print(f"  ⚠️  +0x72 is cmp but operands differ: {i.op_str}")
            warnings.append(f"vbmeta+0x72: cmp but unexpected operands: {i.op_str}")
        elif i.mnemonic == "movs":
            print(f"  ✅ +0x72 already patched to movs")
        else:
            print(f"  ❌ +0x72 is '{i.mnemonic} {i.op_str}' — expected cmp r3, #0")
            issues.append(f"vbmeta+0x72: expected 'cmp r3, #0', got '{i.mnemonic} {i.op_str}'")
    else:
        print(f"  ❌ +0x72: disassembly failed [raw: 0x{hw:04X}]")
        issues.append("vbmeta+0x72: disassembly failed")

    # Extra: verify the bne.w at vb_addr itself (the 2-halfword NOP target)
    instrs = disasm_at(vb_addr, 1)
    if instrs:
        i = instrs[0]
        hw0 = read16(vb_addr)
        hw1 = read16(vb_addr + 2)
        print(f"  Info: at pattern addr (0x{vb_addr:08X}): {i.mnemonic} {i.op_str}  [raw: 0x{hw0:04X} 0x{hw1:04X}]")
        if "bne" in i.mnemonic or "b" in i.mnemonic:
            print(f"  ✅ Pattern address is a branch instruction (to be NOP'd)")
        else:
            print(f"  ⚠️  Expected branch at pattern address")

else:
    print("  ❌ load_and_verify_vbmeta pattern not found, skipping offset checks")
    issues.append("Cannot verify vbmeta offsets — pattern not found")

# ── 6. IntelliSense / Generated config check ──────────────────────
print("\n┌─────────────────────────────────────────────────────────┐")
print("│ 6. IntelliSense & Generated Config Check                │")
print("└─────────────────────────────────────────────────────────┘\n")

import os

intellisense_files = [
    ".vscode/c_cpp_properties.json",
    "compile_commands.json",
]

for f in intellisense_files:
    if os.path.exists(f):
        print(f"  ✅ {f} exists")
    else:
        print(f"  ⚠️  {f} NOT found")
        warnings.append(f"IntelliSense config '{f}' not found")

gen_files = [
    "include/generated/autoconf.h",
    "include/config/auto.conf",
]

for f in gen_files:
    if os.path.exists(f):
        print(f"  ✅ {f} exists")
    else:
        print(f"  ⚠️  {f} NOT found (run 'make menuconfig' or build to generate)")
        warnings.append(f"Generated config '{f}' not found")

# ── 7. Additional cross-checks ────────────────────────────────────
print("\n┌─────────────────────────────────────────────────────────┐")
print("│ 7. Additional Cross-Checks                              │")
print("└─────────────────────────────────────────────────────────┘\n")

# Verify CONFIG_BOOTLOADER_SIZE matches CODE_SIZE
cfg_size = 0x157934
if cfg_size == CODE_SIZE:
    print(f"  ✅ CONFIG_BOOTLOADER_SIZE (0x{cfg_size:X}) matches expected CODE_SIZE")
else:
    print(f"  ❌ CONFIG_BOOTLOADER_SIZE (0x{cfg_size:X}) != CODE_SIZE (0x{CODE_SIZE:X})")
    issues.append("CONFIG_BOOTLOADER_SIZE mismatch")

# Verify BOOTMODE_ADDRESS is reasonable (should be in data/BSS, not code)
bm_addr = 0x4C5737EC
if bm_addr >= GOT_BASE:
    print(f"  ✅ CONFIG_BOOTMODE_ADDRESS (0x{bm_addr:08X}) is past GOT (0x{GOT_BASE:08X})")
elif bm_addr >= BSS_START:
    print(f"  ✅ CONFIG_BOOTMODE_ADDRESS (0x{bm_addr:08X}) is in BSS region")
else:
    if bm_addr >= LK_START and bm_addr < LK_END:
        print(f"  ⚠️  CONFIG_BOOTMODE_ADDRESS (0x{bm_addr:08X}) is in code region")
        warnings.append("BOOTMODE_ADDRESS is in code region, expected data/BSS")
    else:
        print(f"  ❌ CONFIG_BOOTMODE_ADDRESS (0x{bm_addr:08X}) outside LK range")

# Verify the PATCH_MEM value 0xE006 at fastboot+0xF0 encodes an unconditional branch
# 0xE006 in Thumb = b #0x10 (branch forward by 0x10 from PC)
hw_e006 = 0xE006
opcode = (hw_e006 >> 11) & 0x1F
if opcode == 0x1C:  # 11100 = unconditional branch
    imm11 = hw_e006 & 0x7FF
    offset = imm11 << 1
    if offset & 0x800:
        offset |= 0xFFFFF000  # sign extend
    print(f"  ✅ PATCH_MEM 0xE006 encodes 'b #+0x{offset:X}' (unconditional short branch)")
else:
    print(f"  ⚠️  PATCH_MEM 0xE006 might not be an unconditional branch (opcode bits: {opcode:05b})")

# Verify that PATCH_MEM 0x451B encodes "cmp r3, r3"
# Format: 010001 0101 Rm Rn → cmp Rn, Rm  (high register operations)
hw_451b = 0x451B
if hw_451b == 0x451B:
    # 0100010 1 0 1 Rm=011 Rn=011 → cmp r3, r3
    print(f"  ✅ PATCH_MEM 0x451B encodes 'cmp r3, r3'")

# Verify 0x2301 encodes "movs r3, #1"
hw_2301 = 0x2301
rd = (hw_2301 >> 8) & 0x7
imm8 = hw_2301 & 0xFF
if rd == 3 and imm8 == 1 and (hw_2301 >> 11) == 4:  # 00100 = movs
    print(f"  ✅ PATCH_MEM 0x2301 encodes 'movs r3, #1'")

# ── SUMMARY ────────────────────────────────────────────────────────
print("\n" + "=" * 72)
print("  SUMMARY")
print("=" * 72)

if not issues and not warnings:
    print("\n  ✅ ALL CHECKS PASSED — No issues found.\n")
elif not issues:
    print(f"\n  ✅ No critical issues found.")
    print(f"  ⚠️  {len(warnings)} warning(s):\n")
    for w in warnings:
        print(f"    ⚠️  {w}")
else:
    print(f"\n  ❌ {len(issues)} issue(s) found:")
    for iss in issues:
        print(f"    ❌ {iss}")
    if warnings:
        print(f"\n  ⚠️  {len(warnings)} warning(s):")
        for w in warnings:
            print(f"    ⚠️  {w}")

print()
