#include <linux/bpf.h>
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
