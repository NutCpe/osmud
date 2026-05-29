#!/bin/sh

# Copyright 2018 osMUD
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# old example- block osmud.org:
#./create_ip_fw_rule.sh -t REJECT -s lan -d wan -i 192.168.1.147 -t 198.71.233.87 -p 80

# example- mudfile nest.json for nest Thermostat:
# First we block everything:
#uci set firewall.@rule[-1].target=REJECT
#uci set firewall.@rule[-1].proto=all
#uci set firewall.@rule[-1].src=*
#uci set firewall.@rule[-1].src_ip=192.168.2.254
#uci set firewall.@rule[-1].src_port=*
#uci set firewall.@rule[-1].dest=*
#uci set firewall.@rule[-1].dest_ip=*
#uci set firewall.@rule[-1].dest_port=*

# Then create rules based on mudfile
# TO-acl
#./create_ip_fw_rule.sh -t ACCEPT -p any -s lan -i 192.168.2.254 -a 9543 -d wan -j 34.234.205.19 -b 9543
#./create_ip_fw_rule.sh -t ACCEPT -p any -s lan -i 192.168.2.254 -a 9543 -d wan -j 52.72.253.175 -b 9543
#./create_ip_fw_rule.sh -t ACCEPT -p any -s lan -i 192.168.2.254 -a 9543 -d wan -j 54.173.245.126 -b 9543
# FROM-acl
#./create_ip_fw_rule.sh -t ACCEPT -p any -s wan -i 34.234.205.19 -a 9543 -d lan -j 192.168.2.254 -b 9543
#./create_ip_fw_rule.sh -t ACCEPT -p any -s wan -i 52.72.253.175 -a 9543 -d lan -j 192.168.2.254 -b 9543
#./create_ip_fw_rule.sh -t ACCEPT -p any -s wan -i 54.173.245.126 -a 9543 -d lan -j 192.168.2.254 -b 9543 -n

# dest-ip, dest-port, src-port can have a value of "any". This will note write an entry for this feature that blocks everything
# family and protocol can have value of "all"
# in these cases, these UCI values are not set which triggers the rule on any value for these settings

BASEDIR=`dirname "$0"`
usage() { 
  echo "Usage: 
Required: -t <target_firewall_action> -n <rule-name> -i <src-ip> -a <src-port> 
Optional: -p <proto> -ts <src-zone>  -d <dest-zone> -j <dest-ip> -b <dest-port> -c <device host name> -r <syn-rate> -u <syn-burst> -x <max-session> -y <conn-attempt> -z <attempt-time> -g <fin-rate> -k <fin-burst> -l <rst-rate> -q <rst-burst> [-m] [-e] [-o]" 1>&2; 
  exit 2; 
}

TARGET=""
PROTO=""
SRC=""
SRC_IP=""
SRC_PORT=""
DEST=""
DEST_IP=""
DEST_PORT=""
RULE_NAME=""
HOST_NAME=""
FAMILY=""
SYN_RATE=""
SYN_BURST=""
FIN_RATE=""
FIN_BURST=""
RST_RATE=""
RST_BURST=""

# MATCH=""

while getopts 'ht:p:s:i:a:d:j:b:n:f:c:r:u:g:k:l:q:' option; do
  case "$option" in
    t) TARGET=$OPTARG;;
    p) PROTO=$OPTARG;;
    s) SRC=$OPTARG;;
    i) SRC_IP=$OPTARG;;
    a) SRC_PORT=$OPTARG;;
    d) DEST=$OPTARG;;
    j) DEST_IP=$OPTARG;;
    b) DEST_PORT=$OPTARG;;
    n) RULE_NAME=$OPTARG;;
    f) FAMILY=$OPTARG;;
    c) HOST_NAME=$OPTARG;;
    r) SYN_RATE=$OPTARG;;
    u) SYN_BURST=$OPTARG;;
    g) FIN_RATE=$OPTARG;;
    k) FIN_BURST=$OPTARG;;
    l) RST_RATE=$OPTARG;;
    q) RST_BURST=$OPTARG;;
    h|*) usage;;
  esac
done

if [ -z "$TARGET" ]; then
    printf '%s\n' "ERROR: Please specify target firewall action [ACCEPT|REJECT|DENY]!"
    exit 1
fi

if [ -z "$HOST_NAME" ]; then
    printf '%s\n' "ERROR: Please specify target device host name!"
    exit 1
fi

if [ -z "$FAMILY" ]; then
    printf '%s\n' "ERROR: Please specify firewall protocol family [ipv4|ipv6|all]!"
    exit 1
fi

if [ -z "$PROTO" ]; then
    printf '%s\n' "ERROR: Please specify protocol [tcp|udp|all]."
    exit 1
fi

if [ -z "$SRC" ]; then
    printf '%s\n' "ERROR: Please specify source zone!"
    exit 1
fi

if [ -z "$SRC_IP" ]; then
    printf '%s\n' "ERROR: Please specify source ip!"
    exit 1
fi

if [ -z "$SRC_PORT" ]; then
    printf '%s\n' "ERROR: Please specify source port or 'any'."
    exit 1
fi

if [ -z "$DEST" ]; then
    printf '%s\n' "ERROR: Please specify dest zone!"
    exit 1
fi

if [ -z "$DEST_IP" ]; then
    printf '%s\n' "ERROR: Please specify dest ip or 'any'."
    exit 1
fi

if [ -z "$DEST_PORT" ]; then
    printf '%s\n' "ERROR: Please specify dest port or 'any'."
    exit 1
fi

FINAL_HOST_NAME="mud_${HOST_NAME}_${RULE_NAME}"

HOOK_FILE="/etc/osmud/tcp_hooks.sh"
mkdir -p /etc/osmud
touch "$HOOK_FILE"

# We only build hooks for concrete tuples
emit_hooks=false
if [ "$SRC_IP" != "any" ] && [ "$DEST_IP" != "any" ] && [ "$DEST_PORT" != "any" ]; then
  emit_hooks=true
fi

[ "$emit_hooks" != "true" ] && exit 0

# Keep chain names short
SRC_LAST="$(echo "$SRC_IP" | awk -F. '{print $NF}')"
[ -z "$SRC_LAST" ] && SRC_LAST="0"

DEV_ID="d${SRC_LAST}p${DEST_PORT}"

CH_DEV="OTD_${DEV_ID}"
CH_SYN="OSY_${DEV_ID}"
CH_FIN="OFN_${DEV_ID}"
CH_RST="ORS_${DEV_ID}"

HL_SYN="hs_${SRC_LAST}_${DEST_PORT}"
HL_FIN="hf_${SRC_LAST}_${DEST_PORT}"
HL_RST="hr_${SRC_LAST}_${DEST_PORT}"

HOOK_ZONE="zone_${SRC}_forward"

if ! grep -q '### OSMUD_TCP_GUARD INIT ###' "$HOOK_FILE"; then
cat >> "$HOOK_FILE" <<'EOF'
### OSMUD_TCP_GUARD INIT ###
IPT=${IPT:-/usr/sbin/iptables}

$IPT -nL OSMUD_TCP_GUARD >/dev/null 2>&1 || $IPT -N OSMUD_TCP_GUARD

ipt_before_return() {
    CHAIN="$1"
    shift
    POS=$($IPT -L "$CHAIN" --line-numbers -n 2>/dev/null | awk '$2=="RETURN"{print $1; exit}')
    if [ -z "$POS" ]; then
        $IPT -A "$CHAIN" "$@"
    else
        $IPT -I "$CHAIN" "$POS" "$@"
    fi
}

ensure_chain_return() {
    CHAIN="$1"
    $IPT -C "$CHAIN" -j RETURN 2>/dev/null || $IPT -A "$CHAIN" -j RETURN
}
EOF
fi

cat >> "$HOOK_FILE" <<EOF

# =======================================
# Rule: $FINAL_HOST_NAME
# Tuple: $SRC_IP -> $DEST_IP:$DEST_PORT
# =======================================
IPT=\${IPT:-/usr/sbin/iptables}

# 0) Hook guard from fw3 zone chain
\$IPT -C ${HOOK_ZONE} -p tcp -s ${SRC_IP} -d ${DEST_IP} --dport ${DEST_PORT} -j OSMUD_TCP_GUARD 2>/dev/null || \
  \$IPT -I ${HOOK_ZONE} 1 -p tcp -s ${SRC_IP} -d ${DEST_IP} --dport ${DEST_PORT} -j OSMUD_TCP_GUARD

# 1) Ensure device chain + subchains exist
\$IPT -nL "${CH_DEV}" >/dev/null 2>&1 || \$IPT -N "${CH_DEV}"
\$IPT -nL "${CH_SYN}" >/dev/null 2>&1 || \$IPT -N "${CH_SYN}"
\$IPT -nL "${CH_FIN}" >/dev/null 2>&1 || \$IPT -N "${CH_FIN}"
\$IPT -nL "${CH_RST}" >/dev/null 2>&1 || \$IPT -N "${CH_RST}"

# 2) Dispatch from global guard to this device chain
\$IPT -C OSMUD_TCP_GUARD -p tcp -s ${SRC_IP} -d ${DEST_IP} --dport ${DEST_PORT} -j "${CH_DEV}" 2>/dev/null || \
  ipt_before_return OSMUD_TCP_GUARD -p tcp -s ${SRC_IP} -d ${DEST_IP} --dport ${DEST_PORT} -j "${CH_DEV}"

# 3) Device chain ordering
# SYN NEW -> connlimit -> recent -> FIN -> RST -> RETURN
\$IPT -C "${CH_DEV}" -p tcp --syn -m conntrack --ctstate NEW -j "${CH_SYN}" 2>/dev/null || \
  ipt_before_return "${CH_DEV}" -p tcp --syn -m conntrack --ctstate NEW -j "${CH_SYN}"

\$IPT -C "${CH_DEV}" -p tcp --tcp-flags FIN FIN -j "${CH_FIN}" 2>/dev/null || \
  ipt_before_return "${CH_DEV}" -p tcp --tcp-flags FIN FIN -j "${CH_FIN}"

\$IPT -C "${CH_DEV}" -p tcp --tcp-flags RST RST -j "${CH_RST}" 2>/dev/null || \
  ipt_before_return "${CH_DEV}" -p tcp --tcp-flags RST RST -j "${CH_RST}"

ensure_chain_return "${CH_DEV}"
EOF

# ----------------------------
# SYN subchain
# ----------------------------
if [ -n "$SYN_RATE" ] && [ -n "$SYN_BURST" ]; then
cat >> "$HOOK_FILE" <<EOF
# SYN rate limit
\$IPT -C "${CH_SYN}" -p tcp --syn -m conntrack --ctstate NEW -s ${SRC_IP} -d ${DEST_IP} --dport ${DEST_PORT} \
  -m hashlimit --hashlimit-above ${SYN_RATE}/second --hashlimit-burst ${SYN_BURST} \
  --hashlimit-mode srcip,dstport --hashlimit-name ${HL_SYN} -j DROP 2>/dev/null || \
  ipt_before_return "${CH_SYN}" -p tcp --syn -m conntrack --ctstate NEW -s ${SRC_IP} -d ${DEST_IP} --dport ${DEST_PORT} \
  -m hashlimit --hashlimit-above ${SYN_RATE}/second --hashlimit-burst ${SYN_BURST} \
  --hashlimit-mode srcip,dstport --hashlimit-name ${HL_SYN} -j DROP
ensure_chain_return "${CH_SYN}"
EOF
else
cat >> "$HOOK_FILE" <<EOF
ensure_chain_return "${CH_SYN}"
EOF
fi

# ----------------------------
# FIN subchain
# ----------------------------
if [ -n "$FIN_RATE" ] && [ -n "$FIN_BURST" ]; then
cat >> "$HOOK_FILE" <<EOF
# FIN rate limit
\$IPT -C "${CH_FIN}" -p tcp --tcp-flags FIN FIN -s ${SRC_IP} -d ${DEST_IP} --dport ${DEST_PORT} \
  -m hashlimit --hashlimit-above ${FIN_RATE}/second --hashlimit-burst ${FIN_BURST} \
  --hashlimit-mode srcip,dstport --hashlimit-name ${HL_FIN} -j DROP 2>/dev/null || \
  ipt_before_return "${CH_FIN}" -p tcp --tcp-flags FIN FIN -s ${SRC_IP} -d ${DEST_IP} --dport ${DEST_PORT} \
  -m hashlimit --hashlimit-above ${FIN_RATE}/second --hashlimit-burst ${FIN_BURST} \
  --hashlimit-mode srcip,dstport --hashlimit-name ${HL_FIN} -j DROP
ensure_chain_return "${CH_FIN}"
EOF
else
cat >> "$HOOK_FILE" <<EOF
ensure_chain_return "${CH_FIN}"
EOF
fi

# ----------------------------
# RST subchain
# ----------------------------
if [ -n "$RST_RATE" ] && [ -n "$RST_BURST" ]; then
cat >> "$HOOK_FILE" <<EOF
# RST rate limit
\$IPT -C "${CH_RST}" -p tcp --tcp-flags RST RST -s ${SRC_IP} -d ${DEST_IP} --dport ${DEST_PORT} \
  -m hashlimit --hashlimit-above ${RST_RATE}/second --hashlimit-burst ${RST_BURST} \
  --hashlimit-mode srcip,dstport --hashlimit-name ${HL_RST} -j DROP 2>/dev/null || \
  ipt_before_return "${CH_RST}" -p tcp --tcp-flags RST RST -s ${SRC_IP} -d ${DEST_IP} --dport ${DEST_PORT} \
  -m hashlimit --hashlimit-above ${RST_RATE}/second --hashlimit-burst ${RST_BURST} \
  --hashlimit-mode srcip,dstport --hashlimit-name ${HL_RST} -j DROP
ensure_chain_return "${CH_RST}"
EOF
else
cat >> "$HOOK_FILE" <<EOF
ensure_chain_return "${CH_RST}"
EOF
fi

exit 0