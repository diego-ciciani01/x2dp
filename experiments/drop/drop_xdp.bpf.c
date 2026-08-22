#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int baseline_empty(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 192 > data_end)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
