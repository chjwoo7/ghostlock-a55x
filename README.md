# ghostlock-a55x

CVE-2026-43499 target port for the **Samsung Galaxy A55 5G** — `SM-A556B` / `SM-A556E` / `SM-A556S`, Exynos 1480, kernel branch `6.1.157-android14-11`.

[![tools CI](https://github.com/chjwoo7/ghostlock-a55x/actions/workflows/tools-ci.yml/badge.svg)](https://github.com/chjwoo7/ghostlock-a55x/actions/workflows/tools-ci.yml)

**Status: tooling only. No verified `a55x` firmware profile exists yet.**

| Firmware (PDA) | Kernel release | Route | State |
|---|---|---|---|
| `A556EXXU…` | `6.1.157-android14-11-<num>-abA556E…` | TBD | not started |
| — | — | — | — |

Nothing in this repository has been executed on an A55. Read [Status](#status) before assuming otherwise.

## Why this repo exists

CVE-2026-43499 ports are firmware-exact: every offset in a target header comes from **one** `boot.img`, and a profile from a sibling build produces either a failed KASLR slide solve or a kernel panic. There is no A55 target in any published port, and there cannot be one until someone runs the derivation against an A55 `boot.img`.

Existing coverage in the family, for reference:

| Project | CVE | Samsung coverage |
|---|---|---|
| [`Again1996-bit/CVE-2026-98260-GhostKey`](https://github.com/Again1996-bit/CVE-2026-98260-GhostKey) | 2026-98260 | none — profiles derive from OnePlus Ace 3 Pro / OPPO images, and admission is gated on `android15-8` |
| [`YuKongA/ghostlock-app`](https://github.com/YuKongA/ghostlock-app) | 2026-43499 | app-domain runner, no shell bridge |
| [`wxxsfxyzm/GhostLock-Galaxy`](https://github.com/wxxsfxyzm/GhostLock-Galaxy) | 2026-43499 | Z Fold6 `SM-F9560` (Snapdragon) |
| [`BuSung-dev/Root-My-Galaxy-Payloads`](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads) | 2026-43499 | A53 5G `5.10.237`, A36 5G `6.6.46`, **A56 5G `6.6.102`** (device-tested), S24 / S24+ / S24 FE `6.1.157`, S23U `5.15.189` |

The two templates that matter for an A55:

- **A56 5G (`6.6.102`, Exynos 1580)** — the closest verified sibling: same vendor line, same `CONFIG_KDP` / `CONFIG_RKP` / `CONFIG_SECURITY_DEFEX` stack, full chain including KernelSU late-load, device-tested through Shizuku.
- **S24+ / S24 / S24 FE (`6.1.157`)** — same kernel version, all flagged `requiresFreshP0Session`, which is the evidence that a Samsung `6.1.157` kernel takes the P0 (physical) slide oracle rather than the tracefs one.

## Status

Unported. Current gate results live in `docs/porting-notes.md`. The two facts that decide whether an A55 port can work at all:

1. whether `shell` (uid 2000) may write `tracefs` on the A55 user build — `tools/preflight.sh` answers this;
2. whether the A55 bootloader exposes the physical read the P0 route needs — hardware testing only.

Plus one arithmetic gate: the derived `SLIDE_PSELECT_WORD_SHIFT` must be **≤ 3**, otherwise the futex waiter misses the `core_sys_select` stack copy and the route is impossible for that kernel.

## Tooling

### `tools/preflight.sh`

Device-side gates: SELinux mode, `kptr_restrict`, `tracefs` mount and write access, `sched_blocked_reason` event id, `kallsyms` readability, presence of Samsung `kdp_` / `rkp_` / `defex_` symbols, and the module-loading surface.

```sh
adb push tools/preflight.sh /data/local/tmp/ && adb shell sh /data/local/tmp/preflight.sh
```

### `tools/port_a55.py`

Derives a complete target header set from your own `boot.img`, following the upstream firmware-to-profile procedure:

| Derived | How |
|---|---|
| raw ARM64 Image | boot header v4 `kernel_size` at `0x08`, payload at `0x1000`, auto gzip / lz4 / zstd / raw |
| BTF blob | validated raw BTF header (`0xeb9f`, v1, bounds, NUL string section), refuses ambiguous images |
| symbols | `vmlinux-to-elf`, then its own ELF64 / `SHT_SYMTAB` reader — no `llvm-nm` needed |
| `*_OFF` macros | every symbol in the upstream header set, relative to `_text` |
| struct layout | `bpftool btf dump … format raw` for `task_struct`, `file_operations`, `page`, `cred`, `miscdevice`, `selinux_state`, `ctl_table` |
| `SLIDE_TRACEFS_EVENT_ID` | `(__event_sched_blocked_reason − __start_ftrace_events) / 8 + __TRACE_LAST_TYPE` |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | `bl schedule` return site inside `worker_thread` (capstone or `llvm-objdump`) |
| `SLIDE_NFULNL_LOGGER_NAME_OFF` | dereference `nfulnl_logger->name`, assert `"nfnetlink_log"` |
| `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` | walk `random_table[]` `.name` pointers for `"boot_id"` |
| `SLIDE_SYSCTL_BOOTID_OFF`, `ASHMEM_MISC_FOPS_OFF`, `SELINUX_ENFORCING_OFF` | symbol + BTF member offset |
| P0 fingerprint table | 32 rows, slides `0x000000`…`0x1f0000`, qwords at page offsets `0x000`…`0xe00` |

```sh
pip install lz4 vmlinux-to-elf
python tools/port_a55.py --boot boot.img.lz4 --out out-a55x \
       --pda A556EXXU<PDA> --model SM-A556E
```

Outputs `target.h`, `p0_fingerprint.h`, `port-report.md`, plus `kernel`, `vmlinux.elf`, `vmlinux.btf`, `vmlinux-btf.raw` for provenance.

**It cannot derive** `SLIDE_PSELECT_WORD_SHIFT` (needs fd_set / `rt_mutex_waiter` stack analysis), `P0_KERNEL_PHYS_LOAD` (needs `sboot.bin` from the BL archive), or `P0_ORACLE_PROBE_OFFSET` (defined by the payload you build against). It reports each as unresolved rather than guessing, and exits non-zero when anything is missing.

### `tools/test_port.py`

Offline self-test against a synthetic ELF64 + kernel image: symbol base, `nfulnl_logger` name deref, `random_table` `boot_id` slot, P0 table shape, header emission. Runs in CI.

```sh
python tools/test_port.py   # -> selftest OK
```

## Quick start

```sh
# 1. gates and identity
adb shell 'uname -r; getprop ro.build.display.id; getprop ro.build.fingerprint'
adb shell sh /data/local/tmp/preflight.sh

# 2. same-PDA firmware, e.g. samloader-rs
samloader check-update --model SM-A556E --region <CSC> --all --verbose
samloader download --model SM-A556E --region <CSC> --version "<4-part>" --out-file fw.zip
tar -xf fw.zip AP_*.tar.md5 && tar -xf AP_*.tar.md5 boot.img.lz4

# 3. derive
python tools/port_a55.py --boot boot.img.lz4 --out out-a55x --pda <PDA> --model SM-A556E

# 4. drop into a payload tree and build
#    Root-My-Galaxy-Payloads/src/targets/a55x-<PDA>/{target.h,p0_fingerprint.h}
make TARGET=a55x-<PDA> ANDROID_NDK_HOME=~/android-ndk-r29 release
```

The KernelSU side is **not optional and not portable** — see [`kernelsu/README.md`](kernelsu/README.md). A generic module on an Exynos `6.1` kernel dies in `ksu_patch_text()` and takes the phone down through EL2:

```
exynos_report_el2_crash_info+0x53c/0x558 [exynos_el2]
ksu_patch_text_cb+0x150/0x200 [kernelsu]
```

## Known failure modes

| Symptom | Cause |
|---|---|
| `exit=2`, no plausible slide | profile from another build, or `text_offset != 0` mishandled |
| slide solves, inject panics | `cred` / `task_struct` layout taken from a sibling firmware |
| reboot at `ksud late-load`, `exynos_el2` in logs | module does live text patching — rebuild with `CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y` |
| `pselect` route rejects the layout | derived word shift > 3 |
| `boot_id` oracle reads zero | P0 table built without the `probe_offset − slide` conversion |

## Repository layout

```
tools/            port + preflight + self-test
src/targets/      generated per-firmware headers (a55x-<PDA>/), naming rules inside
docs/             A55-specific porting notes, gate results
kernelsu/         vermagic and Samsung KSU build requirements
```

## Contributing

A profile PR is accepted when it carries: firmware identity (model, CSC, 4-part version, `ro.build.fingerprint`, `ro.build.display.id`), kernel `sha256`, `target.h`, `p0_fingerprint.h`, the slide value the payload actually solved, `port-report.md`, and either a successful `id` from the root daemon or the exact crash trace. Profiles without a hardware result are accepted into `docs/` as `experimental`, never into `src/targets/`.

## Credits

Every technique here is upstream work; this repository only adds A55 derivation tooling.

- [`NebuSec/CyberMeowfia`](https://github.com/NebuSec/CyberMeowfia) — original `CVE-2026-43499` exploit source
- [`JoinChang/ghostlock-oneplus`](https://github.com/JoinChang/ghostlock-oneplus) — locked-bootloader Android packaging
- [`YuKongA/ghostlock-app`](https://github.com/YuKongA/ghostlock-app) — one-tap app runner
- [`x-spy/CVE-2026-43499-popsicle`](https://github.com/x-spy/CVE-2026-43499-popsicle) — target generation tooling
- [`BuSung-dev/Root-My-Galaxy-Payloads`](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads) — Samsung target records and the porting procedure this tool automates
- [`wxxsfxyzm/GhostLock-Galaxy`](https://github.com/wxxsfxyzm/GhostLock-Galaxy) — Samsung shell route and route-feasibility reasoning

## License

Apache-2.0, matching the upstream chain. Use only on devices you own or are explicitly authorized to test.
