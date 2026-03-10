//
// SPDX-FileCopyrightText: 2025 Shomy <shomy@shomy.is-a.dev>
//                         2026 Roger Ortiz <me@r0rt1z2.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <board_ops.h>
#include "include/lamu.h"

int is_partition_protected(const char* partition) {
    if (!partition || *partition == '\0') return 1;

    while (*partition && ISSPACE(*partition)) {
        partition++;
    }

    if (*partition == '\0') return 1;

    // These partitions are critical—flashing them incorrectly can lead to a hard brick.
    // To prevent accidental damage, we mark them as protected and block write access.
    if (strcmp(partition, "boot0") == 0 || strcmp(partition, "boot1") == 0 ||
        strcmp(partition, "boot2") == 0 || strcmp(partition, "partition") == 0 ||
        strcmp(partition, "preloader") == 0 || strcmp(partition, "preloader_a") == 0 ||
        strcmp(partition, "preloader_b") == 0) {
        return 1;
    }

    return 0;
}

#ifdef CMD_FLASH_PATTERN
void cmd_flash(const char* arg, void* data, unsigned sz) {
    if (is_partition_protected(arg)) {
        fastboot_fail("Partition is protected");
        return;
    }

    uint32_t addr = SEARCH_PATTERN(LK_START, LK_END, CMD_FLASH_PATTERN);
    if (addr) {
        ((void (*)(const char* arg, void* data, unsigned sz))(addr | 1))(arg, data, sz);
    } else {
        fastboot_fail("Unable to find original cmd_flash");
    }
}
#endif

#ifdef CMD_ERASE_PATTERN
void cmd_erase(const char* arg, void* data, unsigned sz) {
    if (is_partition_protected(arg)) {
        fastboot_fail("Partition is protected");
        return;
    }

    uint32_t addr = SEARCH_PATTERN(LK_START, LK_END, CMD_ERASE_PATTERN);
    if (addr) {
        ((void (*)(const char* arg, void* data, unsigned sz))(addr | 1))(arg, data, sz);
    } else {
        fastboot_fail("Unable to find original cmd_erase");
    }
}
#endif

void cmd_reboot_emergency(const char* arg, void* data, unsigned sz) {
    fastboot_info("The device will reboot into bootrom mode...");
    fastboot_okay("");
    reboot_emergency();
}

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

// The stock "oem efuse enable" writes a 0x200-byte cryptographic token to
// the "efuse" partition at offset 0. On the next boot, the bootloader reads
// this token and blows the hardware eFuse, permanently fusing the device.
//
// "oem efuse disable" is the inverse: it zeroes out the efuse partition,
// removing the token so the eFuse will never be blown. Combined with the
// get_hw_sbc patch (which makes the SoC appear unfused at runtime), this
// permanently disables all eFuse-gated security enforcement.
#define EFUSE_PARTITION_NAME "efuse"
#define EFUSE_TOKEN_SIZE     0x200

void cmd_efuse_disable(const char *arg, void *data, unsigned sz) {
    uint8_t buf[EFUSE_TOKEN_SIZE];
    int has_token = 0;

    // Read the current efuse partition to check if a token is present.
    if (partition_read(EFUSE_PARTITION_NAME, 0, buf, EFUSE_TOKEN_SIZE) < 0) {
        fastboot_fail("failed to read efuse partition");
        return;
    }

    for (int i = 0; i < EFUSE_TOKEN_SIZE; i++) {
        if (buf[i] != 0x00 && buf[i] != 0xFF) {
            has_token = 1;
            break;
        }
    }

    if (!has_token) {
        fastboot_info("efuse partition is already clean");
        fastboot_info("get_hw_sbc patched to return 0 (unfused)");
        fastboot_okay("");
        return;
    }

    // Clear the efuse partition to remove the enable token.
    memset(buf, 0, EFUSE_TOKEN_SIZE);

    if (partition_write(EFUSE_PARTITION_NAME, 0, buf, EFUSE_TOKEN_SIZE) < 0) {
        fastboot_fail("failed to write efuse partition");
        return;
    }

    fastboot_info("efuse token erased successfully");
    fastboot_info("eFuse will NOT be blown on next boot");
    fastboot_info("get_hw_sbc patched to return 0 (unfused)");
    fastboot_okay("");
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
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x4880, 0xB087, 0x4D5A);
    if (addr) {
        printf("Found fastboot command processor at 0x%08X\n", addr);
        
        // "not support on security" call
        NOP(addr + 0x15A, 2);

        // "not allowed in locked state" call
        NOP(addr + 0x166, 2);
        
        // Jump directly to command handler
        PATCH_MEM(addr + 0xF0, 0xE006);
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
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x4FF0, 0x4691, 0xF102);
    if (addr) {
        printf("Found AVB cmdline function at 0x%08X\n", addr);
        
        // NOP out the code that checks the actual device state,
        // forcing libavb to always use the "locked" string.
        NOP(addr + 0x9C, 4);
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
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF47F, 0xAE6B, 0xE688, 0xF8DD);
    if (addr) {
        printf("Found load_and_verify_vbmeta at 0x%08X\n", addr);

        // The chain key check first compares key lengths before calling
        // memcmp. If lengths differ, it skips memcmp and falls straight
        // to the error path. Change "cmp r2, r3" to "cmp r3, r3" so the
        // length check always succeeds, allowing execution to reach the
        // memcmp path (which we NOP below).
        PATCH_MEM(addr - 0x32C, 0x451B);

        // NOP the bne.w that rejects mismatched chained vbmeta keys,
        // falling through to the success path unconditionally.
        NOP(addr, 2);

        // Replace "cmp r3, #0" with "movs r3, #1" so key_is_trusted
        // is always nonzero and the following bne.w takes the success
        // branch.
        PATCH_MEM(addr + 0x72, 0x2301);
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
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0xF7FF, 0xFF63, 0xF3C0);
    if (addr) {
        printf("Found get_vfy_policy at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
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
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0xF7FF, 0xFFF9, 0xB908);
    if (addr) {
        printf("Found secure_state_check at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
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

    // The default flash and erase commands perform no safety checks, allowing
    // writes to critical partitions, like the Preloader, which can easily brick
    // the device.
    //
    // To prevent this, we disable the original handlers and replace them with
    // custom wrappers that verify whether the target partition is protected.
#ifdef FLASH_REGISTER_PATTERN
    addr = SEARCH_PATTERN(LK_START, LK_END, FLASH_REGISTER_PATTERN);
    if (addr) {
        printf("Found cmd_flash_register at 0x%08X\n", addr);
        NOP(addr, 2);
    }
#endif

#ifdef ERASE_REGISTER_PATTERN
    addr = SEARCH_PATTERN(LK_START, LK_END, ERASE_REGISTER_PATTERN);
    if (addr) {
        printf("Found cmd_erase_register at 0x%08X\n", addr);
        NOP(addr, 2);
    }
#endif

    // Disables the `fastboot flashing lock` command to prevent accidental hard bricks.
    //
    // Locking while running a custom or modified LK image can leave the device in an
    // unbootable state after reboot, since the expected secure environment is no longer
    // present.
#ifdef FLASHING_LOCK_REGISTER_PATTERN
    addr = SEARCH_PATTERN(LK_START, LK_END, FLASHING_LOCK_REGISTER_PATTERN);
    if (addr) {
        printf("Found cmd_flashing_lock_register at 0x%08X\n", addr);
        NOP(addr, 2);
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
    fastboot_register("oem efuse disable", cmd_efuse_disable, 1);
    fastboot_register("oem reboot-emergency", cmd_reboot_emergency, 1);
#ifdef CMD_FLASH_PATTERN
    fastboot_register("flash:", cmd_flash, 1);
#endif
#ifdef CMD_ERASE_PATTERN
    fastboot_register("erase:", cmd_erase, 1);
#endif
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

    // As an extra safeguard, we manually disable factory mode by calling the
    // relevant update function directly. This ensures the mode is turned off,
    // even if it was set by another part of the bootloader.
#ifdef TINNO_FACMODE_UPDATE_PATTERN
    addr = SEARCH_PATTERN(LK_START, LK_END, TINNO_FACMODE_UPDATE_PATTERN);
    if (addr) {
        printf("Found tinno_facmode_update at 0x%08X\n", addr);
        ((int (*)(int, int))(addr | 1))(0, 0);
    }
#endif
}
