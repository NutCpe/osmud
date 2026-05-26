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
Optional: -p <proto> -s <src-zone> -d <dest-zone> -j <dest-ip> -b <dest-port> -c <device host name> -f <family> -r <packet-rate> -u <burst-rate>" 1>&2
  exit 0
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
UDP_RATE=""
UDP_BURST=""

while getopts 'ht:p:s:i:a:d:j:b:n:f:c:r:u:' option; do
  case "${option}" in
    t) TARGET="$OPTARG" ;;
    f) FAMILY="$OPTARG" ;;
    n) RULE_NAME="$OPTARG" ;;
    p) PROTO="$OPTARG" ;;
    s) SRC="$OPTARG" ;;
    i) SRC_IP="$OPTARG" ;;
    a) SRC_PORT="$OPTARG" ;;
    d) DEST="$OPTARG" ;;
    j) DEST_IP="$OPTARG" ;;
    b) DEST_PORT="$OPTARG" ;;
    c) HOST_NAME="$OPTARG" ;;
    r) UDP_PACKET="$OPTARG" ;;
    u) UDP_BURST="$OPTARG" ;;
    h|*) usage ;;
  esac
done

# -----------------------------
# Validation
# -----------------------------
if [ -z "${TARGET// }" ]; then
  echo "ERROR: Please specify target firewall action [ACCEPT|REJECT|DENY]!"
  exit 1
fi

if [ -z "${HOST_NAME// }" ]; then
  echo "ERROR: Please specify target device host name!"
  exit 1
fi

if [ -z "${FAMILY// }" ]; then
  echo "ERROR: Please specify firewall protocol family [ipv4|ipv6|all]!"
  exit 1
fi

if [ -z "${PROTO// }" ]; then
  echo "ERROR: Please specify protocol [tcp|udp|all]."
  exit 1
fi

if [ -z "${SRC// }" ]; then
  echo "ERROR: Please specify source zone!"
  exit 1
fi

if [ -z "${SRC_IP// }" ]; then
  echo "ERROR: Please specify source IP!"
  exit 1
fi

if [ -z "${SRC_PORT// }" ]; then
  echo "ERROR: Please specify source port or 'any'."
  exit 1
fi

if [ -z "${DEST// }" ]; then
  echo "ERROR: Please specify destination zone!"
  exit 1
fi

if [ -z "${DEST_IP// }" ]; then
  echo "ERROR: Please specify destination IP or 'any'."
  exit 1
fi

if [ -z "${DEST_PORT// }" ]; then
  echo "ERROR: Please specify destination port or 'any'."
  exit 1
fi

# -----------------------------
# Build a unique per-device rule name
# -----------------------------
SAFE_SRC_IP=$(echo "$SRC_IP" | tr '.' '_')
FINAL_HOST_NAME="mud_${HOST_NAME}_${SAFE_SRC_IP}_${RULE_NAME}"

# -----------------------------
# ACCEPT rule (rate-limited)
# -----------------------------
RULE_SEC=$(uci add firewall rule)

uci set firewall.${RULE_SEC}.enabled='1'
uci set firewall.${RULE_SEC}.name="${FINAL_HOST_NAME}"
uci set firewall.${RULE_SEC}.target="${TARGET}"
uci set firewall.${RULE_SEC}.src="${SRC}"
uci set firewall.${RULE_SEC}.src_ip="${SRC_IP}"
uci set firewall.${RULE_SEC}.dest="${DEST}"

if [ "$PROTO" != "all" ]; then
  uci set firewall.${RULE_SEC}.proto="${PROTO}"
fi

if [ "$FAMILY" != "all" ]; then
  uci set firewall.${RULE_SEC}.family="${FAMILY}"
fi

if [ "$SRC_PORT" != "any" ]; then
  uci set firewall.${RULE_SEC}.src_port="${SRC_PORT}"
fi

if [ "$DEST_IP" != "any" ]; then
  uci set firewall.${RULE_SEC}.dest_ip="${DEST_IP}"
fi

if [ "$DEST_PORT" != "any" ]; then
  uci set firewall.${RULE_SEC}.dest_port="${DEST_PORT}"
fi

if [ -n "$UDP_RATE" ]; then
  uci set firewall.${RULE_SEC}.limit="${UDP_RATE}/second"
fi

if [ -n "$UDP_BURST" ]; then
  uci set firewall.${RULE_SEC}.limit_burst="${UDP_BURST}"
fi

# -----------------------------
# DROP rule (catch-all above limit)
# Only create if rate/burst is configured
# -----------------------------
if [ -n "$UDP_RATE" ] || [ -n "$UDP_BURST" ]; then
  DROP_SEC=$(uci add firewall rule)

  uci set firewall.${DROP_SEC}.enabled='1'
  uci set firewall.${DROP_SEC}.name="${FINAL_HOST_NAME}_drop"
  uci set firewall.${DROP_SEC}.target='DROP'
  uci set firewall.${DROP_SEC}.src="${SRC}"
  uci set firewall.${DROP_SEC}.src_ip="${SRC_IP}"
  uci set firewall.${DROP_SEC}.dest="${DEST}"

  if [ "$PROTO" != "all" ]; then
    uci set firewall.${DROP_SEC}.proto="${PROTO}"
  fi

  if [ "$FAMILY" != "all" ]; then
    uci set firewall.${DROP_SEC}.family="${FAMILY}"
  fi

  if [ "$SRC_PORT" != "any" ]; then
    uci set firewall.${DROP_SEC}.src_port="${SRC_PORT}"
  fi

  if [ "$DEST_IP" != "any" ]; then
    uci set firewall.${DROP_SEC}.dest_ip="${DEST_IP}"
  fi

  if [ "$DEST_PORT" != "any" ]; then
    uci set firewall.${DROP_SEC}.dest_port="${DEST_PORT}"
  fi
fi

exit 0