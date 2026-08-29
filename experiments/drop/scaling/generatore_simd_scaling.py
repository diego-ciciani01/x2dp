#!/bin/bash
#tive-eBPF-SIMD and kfunc SIMD scaling microbenchmarks.
# Default ALU counts: 2, 8, 16, 32, 64.
# Each generated workload is fully unrolled.

from pathlib import Path
import argparse

DEFAULT_COUNTS = [2, 8, 16, 32, 64]


def native_source(n):
    ops = []
    ops.append("    bpf_zmm res = __builtin_bpf_simd_add(a, b);")
    if n >= 2:
        ops.append("    res = __builtin_bpf_simd_xor(res, b);")
    for i in range(3, n + 1):
        if i % 2 == 1:
            ops.append("    res = __builtin_bpf_simd_add(res, b);")
        else:
            ops.append("    res = __builtin_bpf_simd_xor(res, b);")

    return f'''#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef int bpf_zmm __attribute__((vector_size(64)));

SEC("xdp")
int native_simd_{n}(struct xdp_md *ctx)
{{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 192 > data_end)
        return XDP_PASS;

    bpf_zmm a = __builtin_bpf_simd_load(data);
    bpf_zmm b = __builtin_bpf_simd_load(data + 64);

{chr(10).join(ops)}

    __builtin_bpf_simd_store(data + 128, res);

    return XDP_DROP;
}}

char LICENSE[] SEC("license") = "GPL";
'''


def kfunc_caller_source(n):
    return f'''#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

extern void bpf_daisy_simd_{n}(void *mem, __u32 mem__sz) __ksym;

SEC("xdp")
int kfunc_simd_{n}(struct xdp_md *ctx)
{{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 192 > data_end)
        return XDP_PASS;

    bpf_daisy_simd_{n}(data, 192);

    return XDP_DROP;
}}

char LICENSE[] SEC("license") = "GPL";
'''


def call_only_source():
    return '''#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

extern void bpf_daisy_noop(void *mem, __u32 mem__sz) __ksym;

SEC("xdp")
int kfunc_call_only(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 192 > data_end)
        return XDP_PASS;

    bpf_daisy_noop(data, 192);

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
'''


def baseline_checked_source():
    # Different return on the short-packet path intentionally prevents
    # LLVM from deleting the bounds check. With 256-B frames the fast
    # path is XDP_DROP.
    return '''#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int baseline_checked(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 192 > data_end)
        return XDP_PASS;

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
'''


def asm_body(n):
    lines = [
        '        "vmovdqu32   0(%0), %%zmm0\\n\\t"',
        '        "vmovdqu32  64(%0), %%zmm1\\n\\t"',
    ]
    for i in range(1, n + 1):
        if i % 2 == 1:
            lines.append('        "vpaddd     %%zmm1, %%zmm0, %%zmm0\\n\\t"')
        else:
            lines.append('        "vpxord     %%zmm1, %%zmm0, %%zmm0\\n\\t"')
    lines.append('        "vmovdqu32  %%zmm0, 128(%0)\\n\\t"')
    return "\n".join(lines)


def kernel_source(counts):
    funcs = []
    funcs.append('''
__bpf_kfunc void bpf_daisy_noop(void *mem, u32 mem__sz)
{
    if (unlikely(mem__sz < 192))
        return;

    /*
     * Keep the pointer observable to the compiler while doing no data work.
     * This retains the BPF->kfunc boundary, normal function entry/exit,
     * and the size check, but no SIMD/data operation.
     */
    asm volatile("" : : "r"(mem) : "memory");
}
''')

    for n in counts:
        funcs.append(f'''
__bpf_kfunc void bpf_daisy_simd_{n}(void *mem, u32 mem__sz)
{{
    char *p = mem;

    if (unlikely(mem__sz < 192))
        return;

    asm volatile(
{asm_body(n)}
        :
        : "r"(p)
        : "memory"
    );
}}
''')

    ids = ['BTF_ID_FLAGS(func, bpf_daisy_noop)']
    ids.extend(f'BTF_ID_FLAGS(func, bpf_daisy_simd_{n})' for n in counts)

    return f'''// SPDX-License-Identifier: GPL-2.0
/*
 * Generated DAISY SIMD kfunc microbenchmarks.
 *
 * The AVX-512 asm is deliberately unrolled to avoid runtime loop overhead.
 * Verify the final vmlinux disassembly before benchmarking.
 *
 * This follows the same experimental inline-asm approach as the current
 * bpf_daisy_simd implementation. It declares "memory" but not explicit ZMM
 * compiler clobbers; this is acceptable only as an experimental kernel
 * microbenchmark under the same assumptions as the existing implementation.
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/module.h>

__bpf_kfunc_start_defs();

{''.join(funcs)}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(daisy_simd_generated_kfunc_ids)
{chr(10).join(ids)}
BTF_KFUNCS_END(daisy_simd_generated_kfunc_ids)

static const struct btf_kfunc_id_set daisy_simd_generated_kfunc_set = {{
    .owner = THIS_MODULE,
    .set = &daisy_simd_generated_kfunc_ids,
}};

static int __init daisy_simd_generated_kfunc_init(void)
{{
    return register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
                                     &daisy_simd_generated_kfunc_set);
}}
late_initcall(daisy_simd_generated_kfunc_init);
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--counts",
        nargs="+",
        type=int,
        default=DEFAULT_COUNTS,
        help="Even ALU-operation counts, default: 2 8 16 32 64",
    )
    parser.add_argument(
        "--out",
        default="generated_simd_tests",
        help="Output directory",
    )
    args = parser.parse_args()

    counts = sorted(set(args.counts))
    if not counts or any(n < 2 or n % 2 for n in counts):
        raise SystemExit("All --counts must be even integers >= 2")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    (out / "baseline_checked.bpf.c").write_text(baseline_checked_source())
    (out / "kfunc_call_only.bpf.c").write_text(call_only_source())

    for n in counts:
        (out / f"native_simd_{n}.bpf.c").write_text(native_source(n))
        (out / f"kfunc_simd_{n}.bpf.c").write_text(kfunc_caller_source(n))

    (out / "daisy_simd_kfunc_generated.c").write_text(kernel_source(counts))

    lines = [
        "# Generated SIMD benchmark files",
        "",
        "ALU counts: " + ", ".join(map(str, counts)),
        "",
        "- baseline_checked.bpf.c: same 192-byte bounds check, no SIMD/kfunc",
        "- kfunc_call_only.bpf.c: same bounds check + no-op kfunc call",
    ]
    for n in counts:
        lines.append(f"- native_simd_{n}.bpf.c: native custom SIMD, {n} ALU ops")
        lines.append(f"- kfunc_simd_{n}.bpf.c: kfunc SIMD, {n} ALU ops")
    lines.append("- daisy_simd_kfunc_generated.c: kernel-side no-op + all SIMD kfuncs")
    (out / "README.md").write_text("\n".join(lines) + "\n")

    print(f"Generated files in {out}")


if __name__ == "__main__":
    main()

