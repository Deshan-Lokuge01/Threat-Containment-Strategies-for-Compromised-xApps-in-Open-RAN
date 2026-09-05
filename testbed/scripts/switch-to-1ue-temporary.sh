#!/usr/bin/env bash
set -euo pipefail

ROOT="$HOME/Desktop/O-RAN-Testbed-Automation"
GNB="$ROOT/Next_Generation_Node_B"
UE="$ROOT/User_Equipment"
BROKER="$GNB/zmq_broker"

ORIGINAL="$BROKER/multi_ue_scenario_3ue.py"
ACTIVE="$BROKER/multi_ue_scenario.py"
SINGLE="$BROKER/single_ue_scenario.py"

sudo -v

for file in "$ORIGINAL" "$ACTIVE" "$SINGLE"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Missing file: $file"
        exit 1
    fi
done

echo "Stopping gNB and current ZMQ broker..."
cd "$GNB"
./stop.sh

echo "Stopping UE3..."
cd "$UE"
./stop.sh 3 || true

echo "Stopping UE2..."
./stop.sh 2 || true

echo "Starting temporary single-UE gNB/ZMQ mode..."
sudo cp "$SINGLE" "$ACTIVE"

restore_original() {
    sudo cp "$ORIGINAL" "$ACTIVE"
}
trap restore_original EXIT

cd "$GNB"
./run_background.sh

restore_original
trap - EXIT

echo "Waiting for UE1 to reconnect..."

CONNECTED=false

for attempt in $(seq 1 30); do
    UE1_IP=$(sudo ip netns exec ue1 \
        ip -4 -o addr show tun_srsue 2>/dev/null |
        awk '{print $4}' |
        cut -d/ -f1 || true)

    if [ -n "$UE1_IP" ]; then
        sudo ip addr add 10.45.1.1/16 dev ogstun 2>/dev/null || true

        sudo ip netns exec ue1 \
            ip route replace 10.45.0.0/16 \
            dev tun_srsue src "$UE1_IP"

        if sudo ip netns exec ue1 \
            ping -c 1 -W 2 10.45.1.1 >/dev/null 2>&1; then
            CONNECTED=true
            break
        fi
    fi

    sleep 2
done

echo
echo "===== Remaining UE processes ====="
pgrep -af 'srsue.*ue[123]\.conf' || true

echo
echo "===== Memory ====="
free -h

echo
if [ "$CONNECTED" = true ]; then
    echo "SUCCESS: Only UE1 is running and UE1 connectivity is working."
    sudo ip netns exec ue1 ping -c 5 -W 3 10.45.1.1
else
    echo "WARNING: UE2 and UE3 stopped, but UE1 did not reconnect within 60 seconds."
    exit 1
fi
