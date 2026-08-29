#!/bin/bash
set -u

IFACE="enp94s0f0np0"
CPU=1
RUNS=10
DURATION=20
OUT="kfunc_simd_256B.csv"
IRQ=264
echo "run,cycles,instructions,rx_packets,cycles_per_pkt,instructions_per_pkt" > "$OUT"

echo "[*] Interface: $IFACE"
echo "[*] CPU:       $CPU"
echo "[*] Runs:      $RUNS"
echo "[*] Duration:  ${DURATION}s"
echo "[*] Output:    $OUT"
echo

for i in $(seq 1 "$RUNS"); do
    echo "===== RUN $i / $RUNS ====="

    RX_BEFORE=$(cat /sys/class/net/$IFACE/statistics/rx_packets)

    PERF_OUT=$(sudo perf stat \
        -C "$CPU" \
        -e cycles,instructions \
        sleep "$DURATION" 2>&1)

    RX_AFTER=$(cat /sys/class/net/$IFACE/statistics/rx_packets)

    RX_PKTS=$((RX_AFTER - RX_BEFORE))

    CYCLES=$(echo "$PERF_OUT" \
        | awk '/cycles/ && !/ref-cycles/ {gsub(",","",$1); print $1; exit}')

    INSTRUCTIONS=$(echo "$PERF_OUT" \
        | awk '/instructions/ {gsub(",","",$1); print $1; exit}')

    if [[ -z "$CYCLES" || -z "$INSTRUCTIONS" || "$RX_PKTS" -le 0 ]]; then
        echo "[!] Invalid run $i"
        echo "$PERF_OUT"
        echo "RX packets = $RX_PKTS"
        echo
        continue
    fi

    CPP=$(awk -v c="$CYCLES" -v p="$RX_PKTS" \
        'BEGIN {printf "%.4f", c/p}')

    IPP=$(awk -v ins="$INSTRUCTIONS" -v p="$RX_PKTS" \
        'BEGIN {printf "%.4f", ins/p}')

    echo "cycles           = $CYCLES"
    echo "instructions     = $INSTRUCTIONS"
    echo "RX packets       = $RX_PKTS"
    echo "cycles/pkt       = $CPP"
    echo "instructions/pkt = $IPP"

    echo "$i,$CYCLES,$INSTRUCTIONS,$RX_PKTS,$CPP,$IPP" >> "$OUT"

    echo

    # breve pausa tra un run e l'altro
    sleep 2
done

echo "=========================================="
echo "[+] Completed"
echo "[+] Results saved in: $OUT"
echo "=========================================="
