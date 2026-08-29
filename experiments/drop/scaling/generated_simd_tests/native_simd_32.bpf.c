#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef int bpf_zmm __attribute__((vector_size(64)));

SEC("xdp")
int native_simd_32(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 192 > data_end)
        return XDP_PASS;

    bpf_zmm a = __builtin_bpf_simd_load(data);
    bpf_zmm b = __builtin_bpf_simd_load(data + 64);

    bpf_zmm res = __builtin_bpf_simd_add(a, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);
    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);

    __builtin_bpf_simd_store(data + 128, res);

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
