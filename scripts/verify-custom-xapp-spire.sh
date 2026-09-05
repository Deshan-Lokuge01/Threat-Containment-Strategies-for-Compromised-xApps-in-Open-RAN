#!/bin/bash
set -e

NAMESPACE="${1:-ricxapp}"
SELECTOR="zt-xguard/component=custom-xapp"

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

echo ""
echo -e "${BOLD}${CYAN}ZT-XGuard SPIRE/SPIFFE Verification${NC}"
echo -e "${CYAN}Namespace: ${NAMESPACE}${NC}"
echo ""

printf "%-45s %-25s %-15s %-70s\n" "POD" "SERVICEACCOUNT" "SOCKET" "EXPECTED SPIFFE ID"
printf "%-45s %-25s %-15s %-70s\n" "---------------------------------------------" "-------------------------" "---------------" "----------------------------------------------------------------------"

for POD in $(kubectl get pods -n "${NAMESPACE}" -l "${SELECTOR}" -o jsonpath='{.items[*].metadata.name}'); do
    SA=$(kubectl get pod -n "${NAMESPACE}" "${POD}" -o jsonpath='{.spec.serviceAccountName}')
    SPIFFE_ID="spiffe://example.org/ns/${NAMESPACE}/sa/${SA}"

    if kubectl exec -n "${NAMESPACE}" "${POD}" -- test -S /run/spire/sockets/spire-agent.sock 2>/dev/null; then
        SOCKET="${GREEN}MOUNTED${NC}"
    else
        SOCKET="${RED}MISSING${NC}"
    fi

    printf "%-45s %-25s %-15b %-70s\n" "${POD}" "${SA}" "${SOCKET}" "${SPIFFE_ID}"
done

echo ""
echo -e "${BOLD}${CYAN}SPIRE registration entries for ZT-XGuard xApps:${NC}"
kubectl exec -n spire-system spire-server-0 -- \
  /opt/spire/bin/spire-server entry show 2>/dev/null | \
  grep "spiffe://example.org/ns/${NAMESPACE}/sa/" | \
  grep -E "telemetry-monitor|qos-optimizer|traffic-analyzer|resource-optimizer|security-observer" || true

echo ""
echo -e "${GREEN}Verification complete.${NC}"
