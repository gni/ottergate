#!/usr/bin/env bash

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

CONTAINER="ottergate-sandbox-client"
OTTERGATE_IP="172.20.0.53"

# Domains on the allowlist that do not use aggressive Cloudflare anti-bot challenges
ALLOWED_HOSTS=(
    "github.com"
    "registry.npmjs.org"
    "huggingface.co"
)

# Blocked domains
BLOCKED_HOSTS=(
    "google.com"
    "example.com"
    "baidu.com"
    "facebook.com"
    "microsoft.com"
    "amazon.com"
    "reddit.com"
)

echo -e "${BLUE}${BOLD}====================================================${RESET}"
echo -e "${BLUE}${BOLD}      Ottergate Complete Zero-Trust Suite Test      ${RESET}"
echo -e "${BLUE}${BOLD}====================================================${RESET}"

# Check if target container is running
RUNNING=$(docker inspect -f '{{.State.Running}}' "${CONTAINER}" 2>/dev/null)
if [ "$RUNNING" != "true" ]; then
    echo -e "${RED}[FAIL] Sandbox container '${CONTAINER}' is not active.${RESET}"
    exit 1
fi
echo -e "${GREEN}✓ Container is active and ready for testing.${RESET}\n"

PASS_COUNT=0
FAIL_COUNT=0

report_result() {
    local test_name=$1
    local status=$2
    if [ "$status" = "PASS" ]; then
        echo -e "  [${GREEN}PASS${RESET}] $test_name"
        ((PASS_COUNT++))
    else
        echo -e "  [${RED}FAIL${RESET}] $test_name"
        ((FAIL_COUNT++))
    fi
}

log_syscall_trace() {
    local cmd_str=$1
    echo "sys_enter_execve: [$cmd_str]" | docker exec -i "${CONTAINER}" sh -c "cat > /proc/1/fd/1" 2>/dev/null
}

echo -e "${BOLD}--- PHASE 1: Testing DNS Interception (DNS -> Ottergate IP) ---${RESET}"
for host in "${ALLOWED_HOSTS[@]}"; do
    log_syscall_trace "/usr/bin/nslookup $host"
    DNS_RES=$(docker exec "${CONTAINER}" nslookup "$host" 2>&1)
    if echo "$DNS_RES" | grep -q "${OTTERGATE_IP}"; then
        report_result "DNS Resolve Allowed: $host" "PASS"
    else
        report_result "DNS Resolve Allowed: $host" "FAIL"
    fi
done

for host in "${BLOCKED_HOSTS[@]}"; do
    log_syscall_trace "/usr/bin/nslookup $host"
    DNS_RES=$(docker exec "${CONTAINER}" nslookup "$host" 2>&1)
    if echo "$DNS_RES" | grep -q "${OTTERGATE_IP}"; then
        report_result "DNS Resolve Blocked: $host" "PASS"
    else
        report_result "DNS Resolve Blocked: $host" "FAIL"
    fi
done

echo -e "\n${BOLD}--- PHASE 1b: Testing DNS Local Records (MX, TXT, AAAA, NS, A) ---${RESET}"

# 1. MX record lookup
log_syscall_trace "/usr/bin/nslookup -type=mx test-records.loop"
MX_RES=$(docker exec "${CONTAINER}" nslookup -type=mx test-records.loop 2>&1)
if echo "$MX_RES" | grep -q "mail.test-records.loop"; then
    report_result "DNS Resolve MX Record: test-records.loop" "PASS"
else
    report_result "DNS Resolve MX Record: test-records.loop" "FAIL"
fi

# 2. TXT record lookup
log_syscall_trace "/usr/bin/nslookup -type=txt test-records.loop"
TXT_RES=$(docker exec "${CONTAINER}" nslookup -type=txt test-records.loop 2>&1)
if echo "$TXT_RES" | grep -q "v=spf1 -all"; then
    report_result "DNS Resolve TXT Record: test-records.loop" "PASS"
else
    report_result "DNS Resolve TXT Record: test-records.loop" "FAIL"
fi

# 3. AAAA record lookup
log_syscall_trace "/usr/bin/nslookup -type=aaaa test-records.loop"
AAAA_RES=$(docker exec "${CONTAINER}" nslookup -type=aaaa test-records.loop 2>&1)
if echo "$AAAA_RES" | grep -q "2001:db8::1"; then
    report_result "DNS Resolve AAAA Record: test-records.loop" "PASS"
else
    report_result "DNS Resolve AAAA Record: test-records.loop" "FAIL"
fi

# 4. NS record lookup
log_syscall_trace "/usr/bin/nslookup -type=ns test-records.loop"
NS_RES=$(docker exec "${CONTAINER}" nslookup -type=ns test-records.loop 2>&1)
if echo "$NS_RES" | grep -q "ns1.test-records.loop"; then
    report_result "DNS Resolve NS Record: test-records.loop" "PASS"
else
    report_result "DNS Resolve NS Record: test-records.loop" "FAIL"
fi

# 5. A record lookup
log_syscall_trace "/usr/bin/nslookup -type=a test-records.loop"
A_RES=$(docker exec "${CONTAINER}" nslookup -type=a test-records.loop 2>&1)
if echo "$A_RES" | grep -q "10.0.0.1"; then
    report_result "DNS Resolve A Record: test-records.loop" "PASS"
else
    report_result "DNS Resolve A Record: test-records.loop" "FAIL"
fi

echo -e "\n${BOLD}--- PHASE 2: Testing HTTP Egress Control ---${RESET}"
for host in "${ALLOWED_HOSTS[@]}"; do
    log_syscall_trace "/usr/bin/wget -T 10 -O- http://$host"
    HTTP_RES=$(docker exec "${CONTAINER}" wget -T 10 -O- "http://$host" 2>&1)
    if echo "$HTTP_RES" | grep -q "403 Forbidden"; then
        report_result "HTTP Allowed Domain (bypasses firewall): $host" "FAIL"
    else
        report_result "HTTP Allowed Domain (bypasses firewall): $host" "PASS"
    fi
done

for host in "${BLOCKED_HOSTS[@]}"; do
    log_syscall_trace "/usr/bin/wget -T 10 -O- http://$host"
    HTTP_RES=$(docker exec "${CONTAINER}" wget -T 10 -O- "http://$host" 2>&1)
    if echo "$HTTP_RES" | grep -q "403 Forbidden"; then
        report_result "HTTP Blocked Domain (returns 403): $host" "PASS"
    else
        report_result "HTTP Blocked Domain (returns 403): $host" "FAIL"
    fi
done

echo -e "\n${BOLD}--- PHASE 3: Testing HTTPS / SNI Egress Control ---${RESET}"
for host in "${ALLOWED_HOSTS[@]}"; do
    log_syscall_trace "/usr/bin/wget --no-check-certificate -T 10 -O- https://$host"
    HTTPS_RES=$(docker exec "${CONTAINER}" wget --no-check-certificate -T 10 -O- "https://$host" 2>&1)
    if echo "$HTTPS_RES" | grep -q "Connection reset by peer"; then
        report_result "HTTPS Allowed Domain (bypasses SNI block): $host" "FAIL"
    else
        report_result "HTTPS Allowed Domain (bypasses SNI block): $host" "PASS"
    fi
done

for host in "${BLOCKED_HOSTS[@]}"; do
    log_syscall_trace "/usr/bin/wget --no-check-certificate -T 10 -O- https://$host"
    HTTPS_RES=$(docker exec "${CONTAINER}" wget --no-check-certificate -T 10 -O- "https://$host" 2>&1)
    if echo "$HTTPS_RES" | grep -q "Connection reset by peer"; then
        report_result "HTTPS Blocked Domain (aborted by SNI proxy): $host" "PASS"
    else
        report_result "HTTPS Blocked Domain (aborted by SNI proxy): $host" "FAIL"
    fi
done

echo -e "\n${BOLD}--- PHASE 4: Testing SSL/TLS, Custom Headers, and mTLS ---${RESET}"

# 1. Test HTTPS HTTP proxy with client mTLS & Header verification
log_syscall_trace "/usr/bin/curl -s http://secure-api.loop/test-headers"
MTLS_RES=$(docker exec "${CONTAINER}" curl -s http://secure-api.loop/test-headers 2>&1)
if echo "$MTLS_RES" | grep -q '"mtls":true' && echo "$MTLS_RES" | grep -qi "X-Environment"; then
    report_result "HTTPS L7 Proxy mTLS and Injected Headers Check" "PASS"
else
    report_result "HTTPS L7 Proxy mTLS and Injected Headers Check" "FAIL"
    echo "         Details: $MTLS_RES"
fi

# 2. Test SNI Transparent HTTPS proxy with self-signed certificate validation
log_syscall_trace "/usr/bin/curl -s --cacert /app/config/ca.crt https://ottergate.loop/"
SNI_RES=$(docker exec "${CONTAINER}" curl -s --cacert /app/config/ca.crt https://ottergate.loop/ 2>&1)
if echo "$SNI_RES" | grep -q '"tls":true'; then
    report_result "HTTPS SNI Proxy and Certificate Validation Check" "PASS"
else
    report_result "HTTPS SNI Proxy and Certificate Validation Check" "FAIL"
    echo "         Details: $SNI_RES"
fi

echo -e "\n${BLUE}${BOLD}====================================================${RESET}"
echo -e "${BOLD}                Suite Test Summary                 ${RESET}"
echo -e "${BLUE}${BOLD}====================================================${RESET}"
echo -e "  Total Tests Passed: ${GREEN}${PASS_COUNT}${RESET}"
echo -e "  Total Tests Failed: ${RED}${FAIL_COUNT}${RESET}"
echo -e "${BLUE}${BOLD}====================================================${RESET}"

if [ $FAIL_COUNT -eq 0 ]; then
    exit 0
else
    exit 1
fi
