
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef int bpf_zmm __attribute__((vector_size(64)));

static __always_inline int bounds_check(struct xdp_md *ctx,
                                        void **data_out)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 192 > data_end)
        return 0;

    *data_out = data;
    return 1;
}


/*
 * Baseline:
 * nessuna istruzione SIMD.
 */
SEC("xdp")
int baseline_empty(struct xdp_md *ctx)
{
    void *data;

    if (!bounds_check(ctx, &data))
        return XDP_DROP;

    return XDP_PASS;
}


/*
 * SIMD minimal:
 * LOAD + STORE
 *
 * Serve soprattutto per stimare il costo fisso:
 * kernel_fpu_begin/end + wrapper + accesso ZMM.
 */
SEC("xdp")
int simd_0(struct xdp_md *ctx)
{
    void *data;

    if (!bounds_check(ctx, &data))
        return XDP_DROP;

    bpf_zmm a = __builtin_bpf_simd_load(data);

    __builtin_bpf_simd_store(data + 128, a);

    return XDP_PASS;
}


/*
 * 1 coppia:
 * 1 VPADDD
 * 1 VPXORD
 */
SEC("xdp")
int simd_1(struct xdp_md *ctx)
{
    void *data;

    if (!bounds_check(ctx, &data))
        return XDP_DROP;

    bpf_zmm a = __builtin_bpf_simd_load(data);
    bpf_zmm b = __builtin_bpf_simd_load(data + 64);

    bpf_zmm res = a;

    res = __builtin_bpf_simd_add(res, b);
    res = __builtin_bpf_simd_xor(res, b);

    __builtin_bpf_simd_store(data + 128, res);

    return XDP_PASS;
}


/*
 * 2 coppie ADD/XOR
 */
SEC("xdp")
int simd_2(struct xdp_md *ctx)
{
    void *data;

    if (!bounds_check(ctx, &data))
        return XDP_DROP;

    bpf_zmm a = __builtin_bpf_simd_load(data);
    bpf_zmm b = __builtin_bpf_simd_load(data + 64);

    bpf_zmm res = a;

#pragma unroll
    for (int i = 0; i < 2; i++) {
        res = __builtin_bpf_simd_add(res, b);
        res = __builtin_bpf_simd_xor(res, b);
    }

    __builtin_bpf_simd_store(data + 128, res);

    return XDP_PASS;
}


/*
 * 4 coppie ADD/XOR
 */
SEC("xdp")
int simd_4(struct xdp_md *ctx)
{
    void *data;

    if (!bounds_check(ctx, &data))
        return XDP_DROP;

    bpf_zmm a = __builtin_bpf_simd_load(data);
    bpf_zmm b = __builtin_bpf_simd_load(data + 64);

    bpf_zmm res = a;

#pragma unroll
    for (int i = 0; i < 4; i++) {
        res = __builtin_bpf_simd_add(res, b);
        res = __builtin_bpf_simd_xor(res, b);
    }

    __builtin_bpf_simd_store(data + 128, res);

    return XDP_PASS;
}


/*
 * 8 coppie ADD/XOR
 */
SEC("xdp")
int simd_8(struct xdp_md *ctx)
{
    void *data;

    if (!bounds_check(ctx, &data))
        return XDP_DROP;

    bpf_zmm a = __builtin_bpf_simd_load(data);
    bpf_zmm b = __builtin_bpf_simd_load(data + 64);

    bpf_zmm res = a;

#pragma unroll
    for (int i = 0; i < 8; i++) {
        res = __builtin_bpf_simd_add(res, b);
        res = __builtin_bpf_simd_xor(res, b);
    }

    __builtin_bpf_simd_store(data + 128, res);

    return XDP_PASS;
}


/*
 * 16 coppie ADD/XOR
 */
SEC("xdp")
int simd_16(struct xdp_md *ctx)
{
    void *data;

    if (!bounds_check(ctx, &data))
        return XDP_DROP;

    bpf_zmm a = __builtin_bpf_simd_load(data);
    bpf_zmm b = __builtin_bpf_simd_load(data + 64);

    bpf_zmm res = a;

#pragma unroll
    for (int i = 0; i < 16; i++) {
        res = __builtin_bpf_simd_add(res, b);
        res = __builtin_bpf_simd_xor(res, b);
    }

    __builtin_bpf_simd_store(data + 128, res);

    return XDP_PASS;
}


/*
 * 32 coppie ADD/XOR
 */
SEC("xdp")
int simd_32(struct xdp_md *ctx)
{
    void *data;

    if (!bounds_check(ctx, &data))
        return XDP_DROP;

    bpf_zmm a = __builtin_bpf_simd_load(data);
    bpf_zmm b = __builtin_bpf_simd_load(data + 64);

    bpf_zmm res = a;

#pragma unroll
    for (int i = 0; i < 32; i++) {
        res = __builtin_bpf_simd_add(res, b);
        res = __builtin_bpf_simd_xor(res, b);
    }

    __builtin_bpf_simd_store(data + 128, res);

    return XDP_PASS;
}


/*
 * 40 coppie ADD/XOR
 */
SEC("xdp")
int simd_40(struct xdp_md *ctx)
{
	void *data;
	if (!bounds_check(ctx, &data))
	   return XDP_DROP;

	bpf_zmm a = __builtin_bpf_simd_load(data);
	bpf_zmm b = __builtin_bpf_simd_load(data + 64);

	bpf_zmm res = a;
#pragma unroll
	for (int i = 0; i<40; i++){
	    res = __builtin_bpf_simd_add(res, b);
	    res = __builtin_bpf_simd_xor(res, b);

	}
	__builtin_bpf_simd_store(data + 128, res);
	
	return XDP_PASS;	
}



/*
 * 48 coppie ADD/XOR
 */
SEC("xdp")
int simd_48(struct xdp_md *ctx)
{
	void *data;
	if (!bounds_check(ctx, &data))
	   return XDP_DROP;

	bpf_zmm a = __builtin_bpf_simd_load(data);
	bpf_zmm b = __builtin_bpf_simd_load(data + 64);

	bpf_zmm res = a;
#pragma unroll
	for (int i = 0; i<48; i++){
	    res = __builtin_bpf_simd_add(res, b);
	    res = __builtin_bpf_simd_xor(res, b);

	}
	__builtin_bpf_simd_store(data + 128, res);
	
	return XDP_PASS;	
}

/*
 * 56 coppie ADD/XOR
 */
SEC("xdp")
int simd_56(struct xdp_md *ctx)
{
	void *data;
	if (!bounds_check(ctx, &data))
	   return XDP_DROP;

	bpf_zmm a = __builtin_bpf_simd_load(data);
	bpf_zmm b = __builtin_bpf_simd_load(data + 64);

	bpf_zmm res = a;
#pragma unroll
	for (int i = 0; i<56; i++){
	    res = __builtin_bpf_simd_add(res, b);
	    res = __builtin_bpf_simd_xor(res, b);

	}
	__builtin_bpf_simd_store(data + 128, res);
	
	return XDP_PASS;	
}

/*
 * 64 coppie ADD/XOR
 */
SEC("xdp")
int simd_64(struct xdp_md *ctx)
{
    void *data;

    if (!bounds_check(ctx, &data))
        return XDP_DROP;

    bpf_zmm a = __builtin_bpf_simd_load(data);
    bpf_zmm b = __builtin_bpf_simd_load(data + 64);

    bpf_zmm res = a;

#pragma unroll
    for (int i = 0; i < 64; i++) {
        res = __builtin_bpf_simd_add(res, b);
        res = __builtin_bpf_simd_xor(res, b);
    }

    __builtin_bpf_simd_store(data + 128, res);

    return XDP_PASS;
}



/*
 * 80 coppie ADD/XOR
 */
SEC("xdp")
int simd_80(struct xdp_md *ctx)
{
	void *data;
	if (!bounds_check(ctx, &data))
	   return XDP_DROP;

	bpf_zmm a = __builtin_bpf_simd_load(data);
	bpf_zmm b = __builtin_bpf_simd_load(data + 64);

	bpf_zmm res = a;
#pragma unroll
	for (int i = 0; i<80; i++){
	    res = __builtin_bpf_simd_add(res, b);
	    res = __builtin_bpf_simd_xor(res, b);

	}
	__builtin_bpf_simd_store(data + 128, res);
	
	return XDP_PASS;	
}


/*
 * 96 coppie ADD/XOR
 */
SEC("xdp")
int simd_96(struct xdp_md *ctx)
{
	void *data;
	if (!bounds_check(ctx, &data))
	   return XDP_DROP;

	bpf_zmm a = __builtin_bpf_simd_load(data);
	bpf_zmm b = __builtin_bpf_simd_load(data + 64);

	bpf_zmm res = a;
#pragma unroll
	for (int i = 0; i<96; i++){
	    res = __builtin_bpf_simd_add(res, b);
	    res = __builtin_bpf_simd_xor(res, b);

	}
	__builtin_bpf_simd_store(data + 128, res);
	
	return XDP_PASS;	
}

/*
 * 128 coppie ADD/XOR
 */
SEC("xdp")
int simd_128(struct xdp_md *ctx)
{
	void *data;
	if (!bounds_check(ctx, &data))
	   return XDP_DROP;

	bpf_zmm a = __builtin_bpf_simd_load(data);
	bpf_zmm b = __builtin_bpf_simd_load(data + 64);

	bpf_zmm res = a;
#pragma unroll
	for (int i = 0; i<128; i++){
	    res = __builtin_bpf_simd_add(res, b);
	    res = __builtin_bpf_simd_xor(res, b);

	}
	__builtin_bpf_simd_store(data + 128, res);
	
	return XDP_PASS;	
}

char LICENSE[] SEC("license") = "GPL";
