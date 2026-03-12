//
// SPDX-FileCopyrightText: 2025 Shomy <shomy@shomy.is-a.dev>
//                         2026 Roger Ortiz <me@r0rt1z2.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <board_ops.h>
#include "include/lamu.h"

#ifdef FASTBOOT_CMDLIST_ADDR
void cmd_help(const char *arg, void *data, unsigned sz) {
    struct fastboot_cmd *cmd = *(struct fastboot_cmd **)FASTBOOT_CMDLIST_ADDR;

    if (!cmd) {
        fastboot_fail("No commands found!");
        return;
    }

    fastboot_info("Available oem commands:");
    while (cmd) {
        if (cmd->prefix) {
            if (strncmp(cmd->prefix, "oem", 3) == 0) {
                fastboot_info(cmd->prefix);
            }
        }
        cmd = cmd->next;
    }
    fastboot_okay("");
}
#endif

long partition_read(const char* part_name, long long offset, uint8_t* data, size_t size) {
    return ((long (*)(const char*, long long, uint8_t*, size_t))(CONFIG_PARTITION_READ_ADDRESS | 1))(
            part_name, offset, data, size);
}

long partition_write(const char* part_name, long long offset, uint8_t* data, size_t size) {
    uint32_t addr = SEARCH_PATTERN(LK_START, LK_END, PARTITION_WRITE_PATTERN);
    if (addr)
        return ((long (*)(const char*, long long, uint8_t*, size_t))(addr | 1))(
            part_name, offset, data, size);
    return -1;
}

static void handle_recovery_boot(void) {
    if (get_bootmode() != BOOTMODE_RECOVERY || !is_spoofing_enabled())
        return;

    printf("Recovery boot detected, modifying cmdline for unlocked state.\n");

    static const uint32_t cmdline_addrs[] = { CMDLINE1_ADDR, CMDLINE2_ADDR };
    for (int i = 0; i < ARRAY_SIZE(cmdline_addrs); i++) {
        printf("Patching cmdline at 0x%08X\n", cmdline_addrs[i]);
        cmdline_replace((char *)cmdline_addrs[i],
            "androidboot.verifiedbootstate=", "green", "orange");    
    }
}

void parse_bootloader_messages(void) {
    struct misc_message misc_msg = {0};

    if (partition_read("misc", 0, (uint8_t *)&misc_msg, sizeof(misc_msg)) < 0) {
        printf("Failed to read misc partition\n");
        return;
    }

    printf("Read bootloader command: %s\n", misc_msg.command);

    if (strncmp(misc_msg.command, "boot-recovery", 13) == 0) {
        printf("Found boot-recovery, forcing recovery\n");
        set_bootmode(BOOTMODE_RECOVERY);
        memset(&misc_msg, 0, sizeof(misc_msg));
        partition_write("misc", 0, (uint8_t *)&misc_msg, sizeof(misc_msg));
    }
    else if (strncmp(misc_msg.command, "boot-bootloader", 15) == 0) {
        printf("Found boot-bootloader, forcing fastboot\n");
        set_bootmode(BOOTMODE_FASTBOOT);
        memset(&misc_msg, 0, sizeof(misc_msg));
        partition_write("misc", 0, (uint8_t *)&misc_msg, sizeof(misc_msg));
    }
}

static void spoof_lock_state(void) {
    uint32_t addr = 0;

    // On most MediaTek devices, lock state is fetched by calling
    // seccfg_get_lock_state() directly. Some vendors (e.g. Xiaomi)
    // add a wrapper that also checks a custom lock mechanism, but
    // this device does not have one. All callers reach
    // seccfg_get_lock_state() through a single b.w thunk.
    //
    // Rather than patching the function body directly, we redirect
    // the thunk to our own get_lock_state(), keeping the original
    // function intact while covering all call sites with a single
    // patch.
    addr = SEARCH_PATTERN(LK_START, LK_END, LOCK_STATE_PATTERN);
    if (addr) {
        printf("Found seccfg_get_lock_state thunk at 0x%08X\n", addr);
        PATCH_BRANCH(addr, (void*)get_lock_state);
    }

    // LK has two security gates in the fastboot command processor that
    // reject commands with "not support on security" and "not allowed
    // in locked state" errors. When spoofing lock state, these would
    // block all fastboot operations despite the device being actually
    // unlocked underneath.
    //
    // Even without spoofing, we patch these out as a safety measure
    // since OEM-specific checks could still interfere with fastboot
    // commands in unexpected ways.
    //
    // Instead of patching at hardcoded offsets within the function
    // (which break across firmware versions), we use DECODE_BL_TARGET
    // to dynamically locate the BL calls to fastboot_fail inside
    // the security check section and NOP them out.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x4880, 0xB087);
    if (addr) {
        printf("Found fastboot command processor at 0x%08X\n", addr);

        uint32_t fail_target = CONFIG_FASTBOOT_FAIL_ADDRESS & ~1;
        int nop_count = 0;

        for (uint32_t a = addr; a < addr + 0x300 && nop_count < 2; a += 2) {
            uint16_t hi = READ16(a);
            uint16_t lo = READ16(a + 2);

            if ((hi & 0xF800) != 0xF000 || (lo & 0xD000) != 0xD000)
                continue;

            if ((DECODE_BL_TARGET(a) & ~1) == fail_target) {
                printf("NOPing security BL at 0x%08X\n", a);
                NOP(a, 2);
                nop_count++;
            }
        }

        // Find the conditional branch that gates command execution
        // behind the security check and make it unconditional so
        // commands are always processed.
        for (uint32_t a = addr; a < addr + 0x200; a += 2) {
            uint16_t instr = READ16(a);

            if ((instr & 0xF000) == 0xD000 && (instr & 0x0F00) != 0x0E00
                && (instr & 0x0F00) != 0x0F00) {
                uint8_t offset = instr & 0xFF;

                if (offset >= 0x04 && offset <= 0x10) {
                    printf("Patching conditional branch at 0x%08X\n", a);
                    PATCH_MEM(a, 0xE000 | offset);
                    break;
                }
            }
        }
    }

    // Tinno's SSM (Smart Security Management) and OEM config commands
    // check a BSS flag to determine whether the caller has permission.
    // The flag is read by a tiny function that returns 0 (denied) unless
    // the flag is set to a non-zero value. Setting it to 1 unconditionally
    // grants permission for all SSM and OEM config operations (carrier,
    // thinkshield, zerotouch, etc.).
#ifdef TINNO_SSM_PERMISSION_ADDR
    printf("Setting SSM permission flag at 0x%08X\n", TINNO_SSM_PERMISSION_ADDR);
    WRITE32(TINNO_SSM_PERMISSION_ADDR, 1);
#endif

    int spoofing = is_spoofing_enabled();
    fastboot_publish("is-spoofing", spoofing ? "1" : "0");

    if (!spoofing) {
        printf("Bootloader lock status spoofing disabled.\n");
        return;
    }

    printf("Bootloader lock status spoofing enabled, applying patches.\n");

    // AVB adds device state info to the kernel cmdline, but it
    // keeps showing "unlocked" even when we want it to say "locked".
    // This patch forces the cmdline to always use the "locked"
    // string instead of checking the actual device state.
    //
    // We search for a BL to get_lock_state (the function whose thunk
    // we patched above) inside the AVB cmdline builder and NOP it
    // plus the following conditional so libavb always takes the
    // "locked" path.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x4FF0, 0x4691);
    if (addr) {
        printf("Found AVB cmdline function at 0x%08X\n", addr);

        // Search within the function for a BL whose target eventually
        // reaches seccfg_get_lock_state (the function we redirected
        // via LOCK_STATE_PATTERN). Instead of a fragile hardcoded
        // offset, we look for a sequence of BL + CMP + Bcc that forms
        // the device-state check and NOP the entire block.
        int patched = 0;
        for (uint32_t a = addr; a < addr + 0x200 && !patched; a += 2) {
            uint16_t hi = READ16(a);
            uint16_t lo = READ16(a + 2);

            if ((hi & 0xF800) != 0xF000 || (lo & 0xD000) != 0xD000)
                continue;

            // After the BL, look for a CMP + Bcc pair (device state check)
            uint16_t after1 = READ16(a + 4);
            uint16_t after2 = READ16(a + 6);

            // CMP Rn, #imm (0x2800-0x2FFF) followed by Bcc (0xD000-0xDFFF)
            if ((after1 & 0xF800) == 0x2800 && (after2 & 0xF000) == 0xD000) {
                printf("NOPing device state check at 0x%08X\n", a);
                NOP(a, 4);
                patched = 1;
            }
        }
    }

    // When booting into recovery, we need to ensure verifiedbootstate
    // is set to "orange" so fastbootd detects the device as unlocked
    // and allows flashing. We also patch a few other cmdline params
    // (secureboot, device_state) as a precaution in case stock
    // recovery checks them as well.
    addr = SEARCH_PATTERN(LK_START, LK_END, CMDLINE_PREPROCESS_PATTERN);
    if (addr) {
        printf("Found cmdline_pre_process at 0x%08X\n", addr);
        PATCH_CALL(addr, (void *)handle_recovery_boot, TARGET_THUMB);
    }

    // AVB verifies vbmeta public keys in two places: once for the main
    // vbmeta image (validate_vbmeta_public_key) and once for chained
    // vbmeta images (avb_safe_memcmp against the expected key). Both
    // reject the boot if the key doesn't match, causing the "Public key
    // used to sign data rejected" error. We patch both checks so any
    // key is accepted regardless.
    //
    // Instead of using hardcoded offsets (which break across firmware
    // versions and can corrupt unrelated code), we search for the
    // specific instructions dynamically within the function body.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF47F, 0xAE6B);
    if (addr) {
        printf("Found load_and_verify_vbmeta at 0x%08X\n", addr);

        // NOP the bne.w that rejects mismatched chained vbmeta keys,
        // falling through to the success path unconditionally.
        NOP(addr, 2);

        // Search backward for "cmp r3, r2" (0x4513) which compares
        // chain key lengths before memcmp. Change to "cmp r3, r3"
        // (0x451B) so the length check always succeeds.
        for (uint32_t a = addr - 2; a > addr - 0x500 && a > LK_START; a -= 2) {
            if (READ16(a) == 0x4513) {
                printf("Found chain key length CMP at 0x%08X\n", a);
                PATCH_MEM(a, 0x451B);
                break;
            }
        }

        // Search forward for "cmp r3, #0" (0x2B00) which checks
        // key_is_trusted. Replace with "movs r3, #1" (0x2301) so
        // key_is_trusted is always nonzero.
        for (uint32_t a = addr + 2; a < addr + 0x100 && a < LK_END; a += 2) {
            if (READ16(a) == 0x2B00) {
                printf("Found key_is_trusted CMP at 0x%08X\n", a);
                PATCH_MEM(a, 0x2301);
                break;
            }
        }
    }
}

void board_early_init(void) {
    printf("Entering early init for Motorola E15 / G05 / G15 / G17\n");

    uint32_t addr = 0;

    // Regardless of whether spoofing is enabled, we always need to
    // disable image authentication. The user may just be using this
    // custom LK to unlock their device, or they may be spoofing
    // where the locked state would enforce verification.
    //
    // Forcing get_vfy_policy to return 0 skips certificate
    // verification for all partitions and firmware images (boot,
    // recovery, dtbo, SCP, etc.) so the device can boot with
    // modified or unsigned images.
    //
    // The function calls sec_policy_checker and then extracts a
    // bitfield from the result. We find it by searching for the
    // stable prologue + bitfield extraction (UBFX) that follows
    // the BL.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0xF7FF);
    if (addr) {
        // Verify the instruction after the BL is UBFX (0xF3C0)
        uint16_t after_bl = READ16(addr + 4);
        if (after_bl == 0xF3C0) {
            printf("Found get_vfy_policy at 0x%08X\n", addr);
            FORCE_RETURN(addr, 0);
        } else {
            addr = 0;
        }
    }
    // Fallback: try original 4-instruction pattern
    if (!addr) {
        addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0xF7FF, 0xFF63, 0xF3C0);
        if (addr) {
            printf("Found get_vfy_policy (fallback) at 0x%08X\n", addr);
            FORCE_RETURN(addr, 0);
        }
    }

    // Tinno (the ODM) added a post app() check that forcefully
    // relocks the device if it was previously unlocked, completely
    // defeating the purpose of unlocking.
    //
    // They do not verify LK integrity, so we can simply patch the
    // function to return immediately before it does anything.
    addr = SEARCH_PATTERN(LK_START, LK_END, TINNO_COMMERCIAL_LOCK_PATTERN);
    if (addr) {
        printf("Found tinno_commercial_device_force_lock at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // This function determines whether the device is in a secure state.
    // When it returns true, fastboot operations such as flash, erase, and
    // lock/unlock are blocked with "[secure] not allow".
    //
    // We patch it to always return false so that all fastboot commands
    // remain accessible regardless of the device's actual secure state.
    // The pattern B508 (PUSH {R3,LR}) + F7FF (BL nearby) is the
    // prologue. We verify by checking for CBZ/CBNZ (B908/B900) after
    // the BL return.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0xF7FF, 0xFFF9, 0xB908);
    if (addr) {
        printf("Found secure_state_check at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
    if (!addr) {
        // Fallback: search with relaxed BL encoding — prologue + CBNZ
        for (uint32_t a = LK_START; a < LK_END - 8; a += 2) {
            if (READ16(a) == 0xB508) {
                uint16_t w1 = READ16(a + 2);
                // BL to nearby function: F7FF or F7FE
                if ((w1 & 0xFFFE) == 0xF7FE || w1 == 0xF7FF) {
                    uint16_t w3 = READ16(a + 6);
                    if (w3 == 0xB908 || w3 == 0xB900) {
                        printf("Found secure_state_check (relaxed) at 0x%08X\n", a);
                        FORCE_RETURN(a, 0);
                        break;
                    }
                }
            }
        }
    }

    // get_hw_sbc() reads the hardware Secure Boot Controller register to
    // determine whether the SoC has been fused. When it returns non-zero,
    // multiple security checks across LK treat the device as secure and
    // block OEM config and SSM operations with "[non-secure] failed".
    //
    // Patching it to always return 0 makes the device appear unfused,
    // bypassing all SBC-gated checks throughout the bootloader.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0x2360, 0xF2C1, 0x13CE, 0x6818);
    if (addr) {
        printf("Found get_hw_sbc at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // tinno_facmode_init() initializes the factory mode state based on the
    // hardware SBC register value. When get_hw_sbc indicates a fused device,
    // this function sets flags that force the bootloader into factory mode
    // on subsequent boots.
    //
    // Disabling it prevents factory mode from being erroneously activated
    // after patching get_hw_sbc.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x41F0, 0xB084, 0x4D28);
    if (addr) {
        printf("Found tinno_facmode_init at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // tinno_is_facmode() reads a flag from oem_mfd to determine whether
    // factory mode is active. It is checked in over 20 call sites across
    // LK, gating fastboot commands and influencing boot behavior.
    //
    // Forcing it to always return false prevents factory mode from ever
    // being considered active, regardless of what oem_mfd contains.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0x4B05, 0x447B, 0x681B, 0x681B, 0x7918);
    if (addr) {
        printf("Found tinno_is_facmode at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // tinno_carrier_validate() checks a carrier string against a
    // region-specific whitelist. It uses a switch on the carrier group
    // value to select the appropriate list, then iterates through the
    // entries comparing with strncmp. If the carrier is not found in the
    // list, it returns non-zero, causing the "oem config carrier" command
    // to respond with "[non-secure] failed".
    //
    // Patching it to always return 0 makes the bootloader accept any
    // carrier string, including ones not in the original whitelist (e.g.
    // "openmx" which is not present in the factory carrier table).
#ifdef TINNO_CARRIER_VALIDATE_PATTERN
    addr = SEARCH_PATTERN(LK_START, LK_END, TINNO_CARRIER_VALIDATE_PATTERN);
    if (addr) {
        printf("Found tinno_carrier_validate at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
#endif

    // The environment area isn't initialized yet when board_early_init
    // runs, so any get_env calls would return NULL at this stage. We
    // hook a printf call in platform_init that runs right after env
    // initialization completes, it's a convenient entry point since
    // the call itself is non-essential and we need the env to be ready
    // before applying our lock state patches.
    addr = SEARCH_PATTERN(LK_START, LK_END, ENV_INIT_DONE_PATTERN);
    if (addr) {
        printf("Found env_init_done at 0x%08X\n", addr);
        PATCH_CALL(addr, (void*)spoof_lock_state, TARGET_THUMB);
    }

    fastboot_register("oem bldr_spoof", cmd_spoof_bootloader_lock, 0);
#ifdef FASTBOOT_CMDLIST_ADDR
    fastboot_register("oem help", cmd_help, 1);
#endif
}

void board_late_init(void) {
    printf("Entering late init for Motorola G15 / G05 / E15\n");

    uint32_t addr = 0;

    // The stock bootloader ignores boot commands written to the misc partition,
    // making it impossible to programmatically reboot into fastboot or recovery.
    // We implement our own misc parsing so tools like mtkclient or Penumbra can
    // trigger these modes automatically by writing to misc before rebooting.
    parse_bootloader_messages();

    // On unlocked devices, LK shows an orange state warning during boot
    // that also introduces an unnecessary 5 second delay. Forcing the
    // function to return 0 skips both the warning and the delay.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0x4B0E, 0x447B);
    if (addr) {
        printf("Found orange_state_warning at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
}