#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define DEFAULT_REPEAT 1000000

struct simd_packet {
    int input_a[16];
    int input_b[16];
    int output_c[16];
};

static int run_test(int prog_fd,
                    struct simd_packet *pkt,
                    __u32 repeat,
                    __u32 *duration_ns,
                    __u32 *retval)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.test.prog_fd = prog_fd;

    attr.test.data_in = (__u64)(unsigned long)pkt;
    attr.test.data_size_in = sizeof(*pkt);

    attr.test.data_out = (__u64)(unsigned long)pkt;
    attr.test.data_size_out = sizeof(*pkt);

    attr.test.repeat = repeat;

    int ret = syscall(__NR_bpf,
                      BPF_PROG_TEST_RUN,
                      &attr,
                      sizeof(attr));

    if (ret < 0)
        return -1;

    if (duration_ns)
        *duration_ns = attr.test.duration;

    if (retval)
        *retval = attr.test.retval;

    return 0;
}

static void init_packet(struct simd_packet *pkt)
{
    memset(pkt, 0, sizeof(*pkt));

    for (int i = 0; i < 16; i++) {
        pkt->input_a[i] = i * 10;
        pkt->input_b[i] = 5;
    }
}

static int verify_simd1(struct simd_packet *pkt)
{
    int ok = 1;

    for (int i = 0; i < 16; i++) {
        int a = i * 10;
        int b = 5;

        int expected = (a + b) ^ b;
        int got = pkt->output_c[i];

        if (got != expected) {
            fprintf(stderr,
                    "lane %d: expected=%d got=%d\n",
                    i, expected, got);
            ok = 0;
        }
    }

    return ok;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr,
                "Usage: %s <object.bpf.o> <program-name> [repeat]\n",
                argv[0]);
        return 1;
    }

    const char *obj_path = argv[1];
    const char *prog_name = argv[2];

    __u32 repeat = DEFAULT_REPEAT;

    if (argc >= 4)
        repeat = strtoul(argv[3], NULL, 10);

    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;

    int prog_fd;
    int err;

    printf("========================================\n");
    printf(" eBPF SIMD microbenchmark\n");
    printf("========================================\n");
    printf("object : %s\n", obj_path);
    printf("program: %s\n", prog_name);
    printf("repeat : %u\n\n", repeat);

    /*
     * 1. Open ELF
     */
    obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        fprintf(stderr,
                "bpf_object__open_file failed: %s\n",
                strerror(errno));
        return 1;
    }

    /*
     * 2. Load program
     *    -> verifier
     *    -> JIT
     */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr,
                "bpf_object__load failed: %s\n",
                strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    /*
     * 3. Find target program
     */
    prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        fprintf(stderr,
                "program '%s' not found\n",
                prog_name);
        bpf_object__close(obj);
        return 1;
    }

    prog_fd = bpf_program__fd(prog);

    if (prog_fd < 0) {
        fprintf(stderr,
                "invalid program fd\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("[+] Program loaded, fd=%d\n", prog_fd);

    /*
     * 4. Prepare packet
     */
    struct simd_packet pkt;
    init_packet(&pkt);

    /*
     * 5. Warm-up
     *
     * Useful to remove some first-run noise.
     */
    __u32 warmup_duration = 0;
    __u32 warmup_retval = 0;

    if (run_test(prog_fd,
                 &pkt,
                 1000,
                 &warmup_duration,
                 &warmup_retval) < 0) {

        fprintf(stderr,
                "warmup BPF_PROG_TEST_RUN failed: %s\n",
                strerror(errno));

        bpf_object__close(obj);
        return 1;
    }

    /*
     * Reset packet after warm-up because SIMD program
     * writes output_c.
     */
    init_packet(&pkt);

    /*
     * 6. Benchmark
     */
    __u32 duration_ns = 0;
    __u32 retval = 0;

    if (run_test(prog_fd,
                 &pkt,
                 repeat,
                 &duration_ns,
                 &retval) < 0) {

        fprintf(stderr,
                "BPF_PROG_TEST_RUN failed: %s\n",
                strerror(errno));

        bpf_object__close(obj);
        return 1;
    }

    printf("\n--- Results ---\n");

    printf("retval      : %u\n", retval);
    printf("duration    : %u ns\n", duration_ns);

    if (repeat > 0) {
	printf("avg ns/run : %u\n", duration_ns);
	printf("CSV,%s,%u,%u\n",
			    prog_name,
			    repeat, duration_ns);		      
	}

    /*
     * 7. Correctness check.
     *
     * This check only makes sense for simd_1
     * or programs implementing the same expression.
     */
    if (strcmp(prog_name, "simd_1") == 0) {

        if (verify_simd1(&pkt)) {
            printf("verification: OK\n");
        } else {
            printf("verification: FAILED\n");

            bpf_object__close(obj);
            return 1;
        }
    }

    printf("PID=%d, program loaded. Press ENTER to exit...\n",
	  getpid());
    getchar();
    bpf_object__close(obj);

    return 0;
}
