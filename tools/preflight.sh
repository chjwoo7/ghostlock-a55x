#!/usr/bin/env bash
# preflight.sh -- decide whether a CVE-2026-43499 port on this phone can work
# at all, before spending days on offsets. Run it on the device (adb shell) or
# paste the commands manually. Every line is a hard gate for the shell route.
set -u
S() { printf '\n=== %s ===\n' "$1"; }

S "identity"
uname -r
getprop ro.product.model
getprop ro.product.device
getprop ro.build.fingerprint
getprop ro.build.display.id
getprop ro.build.version.sdk
getprop ro.boot.verifiedbootstate
getprop ro.boot.flash.locked
getprop ro.boot.warranty_bit

S "SELinux / kptr"
getenforce
cat /proc/sys/kernel/kptr_restrict 2>/dev/null
cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null
cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null

S "tracefs mount + event id"
mount | grep -i tracefs
ls -ld /sys/kernel/tracing 2>/dev/null
cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id 2>/dev/null \
  || echo "NO sched_blocked_reason event visible"

S "tracefs write from shell (kmem_cache_alloc)"
echo 1 > /sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable 2>&1 && echo "kmem enable OK" || echo "kmem enable DENIED"
echo 1 > /sys/kernel/tracing/tracing_on 2>&1 && echo "tracing_on OK" || echo "tracing_on DENIED"
echo 0 > /sys/kernel/tracing/tracing_on 2>/dev/null
echo 0 > /sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable 2>/dev/null

S "kallsyms readability (rootd/bootstrap needs symbols)"
ls -l /proc/kallsyms
head -3 /proc/kallsyms
grep -cE ' (schedule|worker_thread|nfulnl_logger|sysctl_bootid)$' /proc/kallsyms 2>/dev/null

S "Samsung mitigations present in this kernel"
grep -oE ' (kdp_|rkp_|defex_|samsung_)' /proc/kallsyms 2>/dev/null | sort -u | head -20
ls /sys/fs/selinux/ 2>/dev/null | head
getprop | grep -iE 'knox|rkp|defex|kdp' | head -20

S "module loading surface (KernelSU late-load)"
cat /proc/modules 2>/dev/null | head -5
[ -r /proc/config.gz ] && zcat /proc/config.gz | grep -E 'CONFIG_(MODULES|MODVERSIONS|MODULE_SIG|MODULE_FORCE_LOAD|TRIM_UNUSED_KSYMS|KALLSYMS)' || echo "no /proc/config.gz (read config from boot.img instead)"

S "BTF exposed at runtime (nice-to-have)"
ls -l /sys/kernel/btf/vmlinux 2>/dev/null || echo "no /sys/kernel/btf/vmlinux"

printf '\nVerdict guide:\n'
printf '  * "tracefs write" all OK + sched_blocked_reason id readable -> shell route plausible\n'
printf '  * any DENIED -> the tracefs slide oracle is dead; only the P0 (physical) route remains\n'
printf '  * no sched_blocked_reason -> 6.1 P0 route it is (what S24/S24+/S24FE use)\n'
