#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$HOME/Desktop/O-RAN-Testbed-Automation"
CORE="$ROOT/5G_Core_Network"
GNB="$ROOT/Next_Generation_Node_B"
UE="$ROOT/User_Equipment"
BROKER="$GNB/zmq_broker"

ACTIVE="$BROKER/multi_ue_scenario.py"
THREE_UE="$BROKER/multi_ue_scenario_3ue.py"
SINGLE_UE="$BROKER/single_ue_scenario.py"
UE_LOG="$UE/logs/ue1_stdout.txt"

for file in "$ACTIVE" "$THREE_UE" "$SINGLE_UE"; do
if [ ! -f "$file" ]; then
echo "ERROR: Missing file: $file"
exit 1
fi
done

echo "===== Authenticating sudo ====="
sudo -v

echo "===== Ensuring previous 5G services are stopped ====="
cd "$ROOT"
./stop.sh || true

echo "===== Starting 5G Core ====="
cd "$CORE"
./run.sh

echo "===== Waiting for AMF ====="
AMF_READY=0

for attempt in $(seq 1 120); do
if ./is_amf_ready.sh 2>/dev/null | grep -q "true"; then
AMF_READY=1
echo "AMF is ready."
break
fi

```
sleep 1
```

done

if [ "$AMF_READY" -ne 1 ]; then
echo "ERROR: AMF did not become ready within 120 seconds."
exit 1
fi

echo "===== Starting gNB with single-UE broker ====="
sudo cp "$SINGLE_UE" "$ACTIVE"

restore_three_ue_broker() {
sudo cp "$THREE_UE" "$ACTIVE"
}

trap restore_three_ue_broker EXIT INT TERM

cd "$GNB"
./run_background.sh

restore_three_ue_broker
trap - EXIT INT TERM

echo "===== Starting UE1 only ====="
rm -f "$UE_LOG"

cd "$UE"
./run_background.sh 1

echo "===== Waiting for UE1 attachment ====="
UE_ATTACHED=0

for attempt in $(seq 1 120); do
if grep -q "PDU Session Establishment successful" "$UE_LOG" 2>/dev/null &&
grep -q "RRC NR reconfiguration successful" "$UE_LOG" 2>/dev/null; then
UE_ATTACHED=1
break
fi

```
if ! pgrep -f '[s]rsue.*ue1.conf' >/dev/null; then
    echo "ERROR: UE1 process stopped unexpectedly."
    tail -n 80 "$UE_LOG"
    exit 1
fi

sleep 2
```

done

if [ "$UE_ATTACHED" -ne 1 ]; then
echo "ERROR: UE1 did not attach within 240 seconds."
tail -n 80 "$UE_LOG"
exit 1
fi

echo
echo "============================================"
echo "SUCCESS: UE1 attached successfully."
grep -E 
"PDU Session Establishment successful|RRC NR reconfiguration successful" 
"$UE_LOG" | tail -n 2
echo "============================================"
echo
echo "5G Core, gNB and UE1 are running."
echo "UE2 and UE3 are not running."
echo "Configure the UE1 route manually now."
echo

free -h
