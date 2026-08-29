# Generated SIMD benchmark files

ALU counts: 2, 8, 16, 32, 64

- baseline_checked.bpf.c: same 192-byte bounds check, no SIMD/kfunc
- kfunc_call_only.bpf.c: same bounds check + no-op kfunc call
- native_simd_2.bpf.c: native custom SIMD, 2 ALU ops
- kfunc_simd_2.bpf.c: kfunc SIMD, 2 ALU ops
- native_simd_8.bpf.c: native custom SIMD, 8 ALU ops
- kfunc_simd_8.bpf.c: kfunc SIMD, 8 ALU ops
- native_simd_16.bpf.c: native custom SIMD, 16 ALU ops
- kfunc_simd_16.bpf.c: kfunc SIMD, 16 ALU ops
- native_simd_32.bpf.c: native custom SIMD, 32 ALU ops
- kfunc_simd_32.bpf.c: kfunc SIMD, 32 ALU ops
- native_simd_64.bpf.c: native custom SIMD, 64 ALU ops
- kfunc_simd_64.bpf.c: kfunc SIMD, 64 ALU ops
- daisy_simd_kfunc_generated.c: kernel-side no-op + all SIMD kfuncs
