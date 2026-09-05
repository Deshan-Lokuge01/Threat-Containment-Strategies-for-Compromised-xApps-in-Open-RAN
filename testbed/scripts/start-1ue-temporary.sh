#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$HOME/Desktop/O-RAN-Testbed-Automation"
CORE="$ROOT/5G_Core_Network"
GNB="$ROOT/Next_Generation_Node_B"
UE="$ROOT/User_Equipment"
BROKER="$GNB/zmq_broker"

ORIGINAL="$BROKER/multi_ue_scenario_3ue.py"
ACTIVE="$BROKER/multi_ue_scenario.py"
SINGLE="$BROKER/single_ue_scenario.py"

sudo -v

for file in "$ORIGINAL" "$SINGLE"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Missing $file"
        exit 1
    fi
done

echo "===== Starting 5G Core ====="
cd "$CORE"
./run.sh

echo "===== Waiting for AMF ====="
AMF_READY=false

for attempt in $(seq 1 120); do
    if "$CORE/is_amf_ready.sh" | grep -q "true"; then
        AMF_READY=true
        break
    fi
    sleep 0.5
done

if [ "$AMF_READY" != true ]; then
    echo "ERROR: AMF did not become ready."
    exit 1
fi

echo "AMF is ready."

echo "===== Starting gNB with temporary one-UE broker ====="

sudo cp "$SINGLE" "$ACTIVE"

restore_original() {
    sudo cp "$ORIGINAL" "$ACTIVE"
}

trap restore_original EXIT

cd "$GNB"
./run_background.sh

restore_original
trap - EXIT

echo "===== Starting UE1 only ====="
cd "$UE"
./run_background.sh 1

echo "===== Waiting for UE1 PDU session ====="
PDU_READY=false

for attempt in $(seq 1 60); do
    if grep -q "PDU Session Establishment successful" \
        "$UE/logs/ue1_stdout.txt" 2>/dev/null; then
        PDU_READY=true
        break
    fi

    if ! pgrep -f '[s]rsue --config_file configs/ue1.conf' >/dev/null; then
        echo "ERROR: UE1 process stopped."
        tail -n 80 "$UE/logs/ue1_stdout.txt"
        exit 1
    fi

    sleep 2
done

if [ "$PDU_READY" != true ]; then
    echo "ERROR: UE1 did not establish a PDU session."
    tail -n 80 "$UE/logs/ue1_stdout.txt"
    exit 1
fi

UE1_IP=$(sudo ip netns exec ue1 \
    ip -4 -o addr show tun_srsue |
    awk '{print $4}' |
    cut -d/ -f1)

echo "UE1 IP: $UE1_IP"

sudo ip addr add 10.45.1.1/16 dev ogstun 2>/dev/null || true

sudo ip netns exec ue1 \
    ip route replace 10.45.0.0/16 \
    dev tun_srsue src "$UE1_IP"

echo "===== Testing UE1 ====="

if sudo ip netns exec ue1 ping -c 5 -W 3 10.45.1.1; then
    echo
    echo "SUCCESS: UE1 is connected and UE2/UE3 are not running."
else
    echo
    echo "ERROR: UE1 established a PDU session, but ping failed."
    exit 1
fi

echo
echo "===== UE processes ====="
pgrep -af 'srsue.*ue[123]\.conf' || true

echo
echo "===== Memory ====="
free -h
