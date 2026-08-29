#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

/* Helper / local function definition */
static __always_inline void bpf_daisy_noop(void *mem, u32 mem__sz)
{
    if (mem__sz < 192)
        return;

    asm volatile("" : : "r"(mem) : "memory");
}

/* XDP program entry point */
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    bool fpu_active = false;

    /* Bounds check before accessing 192 bytes */
    if (data + 192 > data_end)
        return XDP_DROP;

    bpf_daisy_noop(data, 192);

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
