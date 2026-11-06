# A55-specific porting notes

Upstream procedure: [`Root-My-Galaxy-Payloads/docs/PORTING.md`](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/blob/main/docs/PORTING.md). This file records only what differs on `a55x` (Exynos 1480, `6.1.157-android14-11`).

## 1. Kernel release string shape

Samsung 6.1 builds on this branch look like:

```
6.1.157-android14-11-<buildnumber>-abA556EXXU<PDA>
```

For comparison, verified siblings:

| Device | `uname -r` |
|---|---|
| S24 FE `SM-S721N` | `6.1.157-android14-11` (unsuffixed in the port doc; `-ab` form on device) |
| S24+ `SM-S926B` | `6.1.157-android14-11-…` |
| A56 5G `SM-A566E` | `6.6.102-android15-8-abA566EXXSCCZG6-4k` |

Two consequences:

- the profile key is the **complete** `uname -r`, not `6.1.157`. A match on `6.1.157` alone is always a false positive;
- OnePlus-style `-o-g<sha>` strings from the GhostKey profiles will never match, which is why that tool refuses Samsung devices on top of its `android15-8` gate.

## 2. Route selection

| Condition | Route |
|---|---|
| `sched_blocked_reason` visible and `tracefs` writable from shell | tracefs oracle, `SLIDE_TRACEFS_EVENT_ID` + `SLIDE_TRACEFS_WORKER_CALLER_OFF` |
| either denied | P0 physical oracle, `P0_*` + `p0_fingerprint.h` |

All three shipped Samsung `6.1.157` targets are marked `requiresFreshP0Session`, which is the strongest available signal that an A55 on `6.1.157` will need the P0 route. `tools/preflight.sh` decides it empirically on the actual phone.

P0 details that are easy to get wrong:

- `P0_KERNEL_PHYS_LOAD` comes from the branch before `Starting kernel…` in `sboot.bin` (BL archive), not from `boot.img`. The S24 FE record shows the sboot sequence `adrp x8 / ldr w8,[x8,#0xd08] / mov w9,#-0x80000000 / add x19,x8,x9 / blr x19`, and `P0_KERNEL_PHYS_LOAD = text_offset + 0x80000000`. With `text_offset == 0` it collapses to `0x80000000`; `tools/port_a55.py` flags any non-zero `text_offset` instead of assuming.
- The oracle table maps the **actual** slide to bytes read at `P0_ORACLE_PROBE_OFFSET − slide`. Skipping that conversion makes the sample look like the slide and the direct-map verification read zero.

## 3. `SLIDE_PSELECT_WORD_SHIFT`

`core_sys_select` copies only `3 × FDS_BYTES(nfds)` of user `fd_set` data onto the kernel stack — qwords `0..14` for `nfds = 320`. The fake `rt_mutex_waiter` must land inside that controllable zone:

```
waiter_start_word + 11 (lock field) <= 14
```

so the derived shift must be `<= 3`. Derive it from `core_sys_select` / `do_pselect` disassembly and verify every waiter member against its BTF raw offset. A shift of `0` means waiter qword zero overlaps the first logical fd-set qword; it is not a default. If the layout is infeasible there is nothing to port on that kernel — stop before building anything.

## 4. BTF

`bpftool` needs an ELF container and will not pull BTF out of a raw ARM64 Image. Extract the blob first: magic `0xeb9f`, version 1, flags 0, `hdr_len >= 24`, section bounds inside the image, NUL byte at the start of the string section. `port_a55.py` implements exactly that validation and refuses multiple candidates.

If the A55 kernel ships without BTF (as with `SM-A155N` on 5.10), the no-BTF procedure applies: `CONFIG_TRIM_UNUSED_KSYMS=y`, build the module with `KBUILD_MODPOST_WARN=1`, keep `.symtab`/`.strtab`, require a zero-length `__versions`, and let KernelSU's late loader relocate undefined symbols from `/proc/kallsyms`.

## 5. Offset provenance rules

- Never copy an offset between builds. `6.6.118` and `6.6.127` differ; so do two `6.1.157` builds.
- `ASHMEM_MISC_FOPS_OFF` is not a symbol: it is `ashmem_misc + offsetof(struct miscdevice, fops)`.
- The netfilter trio is distinct: `nfulnl_logger` object address, the `"nfnetlink_log"` string its first qword points at, and the separate `loggers[][]` registry. Collapsing them breaks the text-base leak.
- `random_table[]` `boot_id` has two addresses: the writable `.data` pointer slot (temporarily repointed, then restored) and the real `sysctl_bootid` storage.

## 6. Gate results

Fill in after running `tools/preflight.sh` on the target phone.

| Gate | Expected | Observed |
|---|---|---|
| `uname -r` | `6.1.157-android14-11-…-abA556…` | |
| `tracefs` mount | present | |
| `tracefs` write from shell | denied (Samsung user build) | |
| `sched_blocked_reason` id | readable → tracefs route | |
| `kptr_restrict` | `2` | |
| Samsung `kdp_` / `rkp_` / `defex_` symbols | present | |
| `P0` physical read reachable | unknown | |
| BTF in `boot.img` | present (`android14-6.1` GKI) | |
