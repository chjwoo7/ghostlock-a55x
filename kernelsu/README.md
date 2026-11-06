# kernelsu/

The root primitive and KernelSU are two separate problems. Getting uid 0 does not imply a working KernelSU on an Exynos Samsung kernel.

## Non-negotiable build properties

The module's `vermagic` must equal the device's **complete** `uname -r` plus the exact feature string:

```
vermagic: 6.1.157-android14-11-<buildnumber>-abA556<...> SMP preempt mod_unload modversions aarch64
uname -r:  6.1.157-android14-11-<buildnumber>-abA556<...>
```

Build flags that matter on this SoC:

```
CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y
```

Without it, `ksu_patch_text()` enters `stop_machine`, Samsung's EL2 monitor catches the live text write, and the phone reboots during `ksud late-load`:

```
exynos_report_el2_crash_info+0x53c/0x558 [exynos_el2]
ksu_patch_text_cb+0x150/0x200 [kernelsu]
```

With it set, the syscall-table dispatcher falls through to the RKP kretprobe/kprobe path and the SELinux-hide slot patches fail closed instead of tripping EL2.

## Source and patch

- KernelSU tag `v3.2.5`, commit `b0bc817b4e966aa6aa830834eaf6ef765d821d40`, plus the repository Samsung KDP/RKP/DEFEX patch.
- Build container used by the verified Samsung targets: `ghcr.io/ylarod/ddk-min:android15-6.6-<date>`, with the DDK release overridden to the target release.
- Run `check_symbol` against the **target** `vmlinux.elf`, not the DDK vmlinux.

## Config to confirm on the target kernel

```
CONFIG_MODULES=y
CONFIG_MODVERSIONS=y
CONFIG_MODULE_SIG_ALL=y
# CONFIG_MODULE_SIG_FORCE is not set
# CONFIG_MODULE_FORCE_LOAD is not set
CONFIG_TRIM_UNUSED_KSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_KDP=y
CONFIG_RKP=y
CONFIG_SECURITY_DEFEX=y
```

`CONFIG_TRIM_UNUSED_KSYMS=y` is what forces the manual-relocation build: keep `.symtab`/`.strtab`, require a zero-length `__versions`, and let the late loader resolve undefined symbols from `/proc/kallsyms`.

## Static checks before shipping a pair

```
__versions size: 0
module version entries: 0
missing from target symbol table: 0
target CRC mismatches: 0
modinfo vermagic == target uname -r + " SMP preempt mod_unload modversions aarch64"
```

## Hardware checks

1. root daemon returns uid 0 (`context=u:r:kernel:s0`);
2. `ksud late-load` completes without a reboot;
3. KernelSU Manager accepts the installed version;
4. `su -c id` under `enforcing`;
5. after reboot, everything is gone again — this is a temporary root, nothing is persisted.
