#/bin/bash
set -euo pipefail

IFACE="enp94s0f0np0"
CPU=1
IRQ=272
RUNS=10
DURATION=20

BASE_DIR="$(pwd)"
NATIVE_DIR="$BASE_DIR/native_csv"
KFUNC_DIR="$BASE_DIR/kfunc_csv"
BASELINE_DIR="$BASE_DIR/baseline_csv"

PIN_DIR="/sys/fs/bpf/daisy"
PIN_PATH="$PIN_DIR/test"

mkdir -p "$NATIVE_DIR" "$KFUNC_DIR" "$BASELINE_DIR"

sudo mkdir -p "$PIN_DIR"

check_setup() {
    echo "[*] Checking setup..."

    IRQ_CPU=$(cat /proc/irq/$IRQ/smp_affinity_list)

    if [[ "$IRQ_CPU" != "$CPU" ]]; then
        echo "[!] IRQ $IRQ is on CPU $IRQ_CPU, expected CPU $CPU"
        exit 1
    fi

    FPU=$(cat /sys/module/i40e/parameters/daisy_fpu_napi)

    if [[ "$FPU" != "Y" ]]; then
        echo "[!] daisy_fpu_napi is not enabled"
        exit 1
    fi

    echo "[+] IRQ $IRQ -> CPU $CPU"
    echo "[+] daisy_fpu_napi = Y"
}

detach_xdp() {
    sudo bpftool net detach xdp dev "$IFACE" 2>/dev/null || true
    sudo ip link set dev "$IFACE" xdp off 2>/dev/null || true

    sudo rm -f "$PIN_PATH"
}

attach_native() {
    OBJ="$1"

    echo "[*] Attaching native program: $OBJ"

    detach_xdp

    sudo ip link set dev "$IFACE" xdpdrv \
        obj "$OBJ" sec xdp

    sleep 1

    sudo bpftool net
}




verify_xdp_attached() {
    local NET_OUT

    NET_OUT=$(sudo bpftool net)

    if ! grep -Fq "$IFACE" <<< "$NET_OUT"; then
        echo "[ERROR] Nessun programma XDP attaccato a $IFACE"
        echo "$NET_OUT"
        exit 1
    fi

    echo "[+] XDP program attached to $IFACE"
}

attach_kfunc() {
    OBJ="$1"

    echo "[*] Attaching kfunc program: $OBJ"

    detach_xdp

    sudo rm -f "$PIN_PATH"

    sudo bpftool prog load \
        "$OBJ" \
        "$PIN_PATH" \
        type xdp

    sudo bpftool net attach xdp \
        pinned "$PIN_PATH" \
        dev "$IFACE"

    sleep 1

    sudo bpftool net
}


run_benchmark() {
    TEST_NAME="$1"
    OUT="$2"

    echo
    echo "=========================================="
    echo "TEST: $TEST_NAME"
    echo "OUTPUT: $OUT"
    echo "=========================================="

    echo \
"run,cycles,instructions,rx_packets,cycles_per_pkt,instructions_per_pkt" \
        > "$OUT"

    for i in $(seq 1 "$RUNS"); do

        echo
        echo "===== RUN $i / $RUNS ====="

        PERF_OUT=$(sudo perf stat \
            -C "$CPU" \
            -e cycles,instructions \
            -- bash -c "
                A=\$(cat /sys/class/net/$IFACE/statistics/rx_packets)

                sleep $DURATION

                B=\$(cat /sys/class/net/$IFACE/statistics/rx_packets)

                echo RX_PACKETS=\$((B-A))
            " 2>&1)

RX_PKTS=$(echo "$PERF_OUT" \
    | awk -F= '/RX_PACKETS=/ {
        gsub(/[[:space:]]/,"",$2);
        print $2
    }')

CYCLES=$(echo "$PERF_OUT" \
    | awk '/cycles/ && !/ref-cycles/ {
        gsub(",","",$1);
        print $1;
        exit
    }')

INSTRUCTIONS=$(echo "$PERF_OUT" \
    | awk '/instructions/ {
        gsub(",","",$1);
        print $1;
        exit
    }')



        if [[ -z "$RX_PKTS" ||
              -z "$CYCLES" ||
              -z "$INSTRUCTIONS" ||
              "$RX_PKTS" -le 0 ]]; then

            echo "[!] Invalid run"
            echo "$PERF_OUT"
            exit 1
        fi

        CPP=$(awk \
            -v c="$CYCLES" \
            -v p="$RX_PKTS" \
            'BEGIN {printf "%.4f", c/p}')

        IPP=$(awk \
            -v i="$INSTRUCTIONS" \
            -v p="$RX_PKTS" \
            'BEGIN {printf "%.4f", i/p}')

        echo "cycles           = $CYCLES"
        echo "instructions     = $INSTRUCTIONS"
        echo "RX packets       = $RX_PKTS"
        echo "cycles/pkt       = $CPP"
        echo "instructions/pkt = $IPP"

        echo \
"$i,$CYCLES,$INSTRUCTIONS,$RX_PKTS,$CPP,$IPP" \
            >> "$OUT"

        sleep 2
    done
}


echo "=========================================="
echo "      DAISY SIMD BENCHMARK CAMPAIGN"
echo "=========================================="

sudo -v

check_setup

# --------------------------------------------------
# Baseline
# --------------------------------------------------

attach_native "baseline_checked.bpf.o"
verify_xdp_attached

run_benchmark \
    "baseline_checked" \
    "$BASELINE_DIR/baseline_checked_256B.csv"


# --------------------------------------------------
# Native SIMD
# --------------------------------------------------

for N in 2 8 16 32 64; do

    OBJ="native_simd_${N}.bpf.o"

    attach_native "$OBJ"
    verify_xdp_attached

    run_benchmark \
        "native_simd_${N}" \
        "$NATIVE_DIR/native_simd_${N}_256B.csv"

done


# --------------------------------------------------
# Kfunc call-only
# --------------------------------------------------

attach_kfunc "kfunc_call_only.bpf.o"
verify_xdp_attached

run_benchmark \
    "kfunc_call_only" \
    "$KFUNC_DIR/kfunc_call_only_256B.csv"


# --------------------------------------------------
# Kfunc SIMD
# --------------------------------------------------

for N in 2 8 16 32 64; do

    OBJ="kfunc_simd_${N}.bpf.o"

    attach_kfunc "$OBJ"
    verify_xdp_attached

    run_benchmark \
        "kfunc_simd_${N}" \
        "$KFUNC_DIR/kfunc_simd_${N}_256B.csv"

done


# --------------------------------------------------
# Cleanup
# --------------------------------------------------

detach_xdp

echo
echo "=========================================="
echo "[+] ALL BENCHMARKS COMPLETED"
echo "=========================================="

echo
echo "[+] Baseline:"
ls -1 "$BASELINE_DIR"

echo
echo "[+] Native:"
ls -1 "$NATIVE_DIR"

echo
echo "[+] Kfunc:"
ls -1 "$KFUNC_DIR"
