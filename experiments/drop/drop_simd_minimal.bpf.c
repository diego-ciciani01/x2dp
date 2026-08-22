#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef int bpf_zmm __attribute__((vector_size(64)));

SEC("xdp")
int simd_minimal(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 192 > data_end)
        return XDP_DROP;

    bpf_zmm a = __builtin_bpf_simd_load(data);
    __builtin_bpf_simd_store(data + 128, a);

    return XDP_PASS;
}
