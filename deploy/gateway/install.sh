#!/usr/bin/env bash
set -euo pipefail
umask 077

# 仅供学习、研究与技术交流；请遵守当地法律和服务条款，禁止经营 VPN、公共代理或绕过访问控制。
SERVICE_USER=gbf-gateway
SERVICE_GROUP=gbf-gateway
CONFIG_DIR=/etc/gbf-power/gateway
LIB_DIR=/usr/local/lib/gbf-power
BIN_PATH="$LIB_DIR/gbf-activation"
UNIT_PATH=/etc/systemd/system/gbf-gateway.service
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
UNIT_SOURCE="$SCRIPT_DIR/../systemd/gbf-gateway.service"

usage() {
  echo "usage: $0 --binary FILE --config-template FILE --rules FILE --node-id ID --control-url URL --control-cert-sha256 HEX --capacity-bps NUMBER" >&2
  exit 2
}

binary_source= config_template= rules_source= node_id= control_url= control_pin= capacity_bps=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary) [ "$#" -ge 2 ] || usage; binary_source=$2; shift 2 ;;
    --config-template) [ "$#" -ge 2 ] || usage; config_template=$2; shift 2 ;;
    --rules) [ "$#" -ge 2 ] || usage; rules_source=$2; shift 2 ;;
    --node-id) [ "$#" -ge 2 ] || usage; node_id=$2; shift 2 ;;
    --control-url) [ "$#" -ge 2 ] || usage; control_url=$2; shift 2 ;;
    --control-cert-sha256) [ "$#" -ge 2 ] || usage; control_pin=$2; shift 2 ;;
    --capacity-bps) [ "$#" -ge 2 ] || usage; capacity_bps=$2; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$binary_source" ] && [ -n "$config_template" ] && [ -n "$rules_source" ] && [ -n "$node_id" ] && [ -n "$control_url" ] && [ -n "$control_pin" ] && [ -n "$capacity_bps" ] || usage
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

canonical_file() {
  resolved=$(readlink -f -- "$1")
  [ -f "$resolved" ] && [ ! -L "$1" ] || { echo "input must be a regular, non-symlink file: $1" >&2; exit 1; }
  printf '%s\n' "$resolved"
}
binary_source=$(canonical_file "$binary_source")
config_template=$(canonical_file "$config_template")
rules_source=$(canonical_file "$rules_source")
unit_source=$(canonical_file "$UNIT_SOURCE")
case "$node_id" in tokyo_cn2|osaka) ;; *) echo "unsupported node id" >&2; exit 1 ;; esac
printf '%s' "$control_url" | grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$' || { echo "invalid control URL" >&2; exit 1; }
printf '%s' "$control_pin" | grep -Eq '^[0-9a-fA-F]{64}$' || { echo "invalid control certificate pin" >&2; exit 1; }
printf '%s' "$capacity_bps" | grep -Eq '^[1-9][0-9]{5,11}$' || { echo "invalid capacity" >&2; exit 1; }

getent group "$SERVICE_GROUP" >/dev/null || groupadd --system "$SERVICE_GROUP"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --gid "$SERVICE_GROUP" --home-dir "$CONFIG_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -o root -g root -m 0755 "$LIB_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$CONFIG_DIR"

stage=$(mktemp -d "$LIB_DIR/.gateway-stage.XXXXXX")
cleanup() { rm -rf -- "$stage"; }
trap cleanup EXIT INT TERM
install -m 0755 "$binary_source" "$stage/gbf-activation"
sed \
  -e 's|${NODE_ID}|'"$node_id"'|g' \
  -e 's|${CONTROL_URL}|'"$control_url"'|g' \
  -e 's|${CONTROL_CERT_SHA256}|'"$control_pin"'|g' \
  -e 's|${CAPACITY_BPS}|'"$capacity_bps"'|g' \
  "$config_template" >"$stage/config.json"
if grep -Eq '\$\{[A-Z0-9_]+\}' "$stage/config.json"; then
  echo "unresolved gateway configuration placeholder" >&2
  exit 1
fi
install -m 0644 "$rules_source" "$stage/rules.json"
install -m 0644 "$unit_source" "$stage/gbf-gateway.service"
chown "$SERVICE_USER:$SERVICE_GROUP" "$stage/config.json" "$stage/rules.json"
chmod 0600 "$stage/config.json"
"$stage/gbf-activation" check-gateway-config --config "$stage/config.json"

host_key="$CONFIG_DIR/ssh_host_ed25519_key"
node_key="$CONFIG_DIR/node_ed25519"
if [ ! -e "$host_key" ]; then
  runuser -u "$SERVICE_USER" -- ssh-keygen -q -t ed25519 -N '' -C gbf-gateway-host -f "$host_key"
fi
if [ ! -e "$node_key" ]; then
  runuser -u "$SERVICE_USER" -- ssh-keygen -q -t ed25519 -N '' -C gbf-gateway-node -f "$node_key"
fi
chown "$SERVICE_USER:$SERVICE_GROUP" "$host_key" "$node_key" "$host_key.pub" "$node_key.pub"
chmod 0600 "$host_key" "$node_key"
chmod 0644 "$host_key.pub" "$node_key.pub"

backup="$stage/backup"
install -d -m 0700 "$backup"
for pair in \
  "$BIN_PATH:binary" \
  "$CONFIG_DIR/config.json:config" \
  "$CONFIG_DIR/rules.json:rules" \
  "$UNIT_PATH:unit"; do
  target=${pair%%:*}; name=${pair##*:}
  if [ -e "$target" ]; then cp -a -- "$target" "$backup/$name"; else : >"$backup/$name.absent"; fi
done

install -m 0755 "$stage/gbf-activation" "$BIN_PATH.new" && mv -f -- "$BIN_PATH.new" "$BIN_PATH"
install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0600 "$stage/config.json" "$CONFIG_DIR/config.json.new" && mv -f -- "$CONFIG_DIR/config.json.new" "$CONFIG_DIR/config.json"
install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0644 "$stage/rules.json" "$CONFIG_DIR/rules.json.new" && mv -f -- "$CONFIG_DIR/rules.json.new" "$CONFIG_DIR/rules.json"
install -m 0644 "$stage/gbf-gateway.service" "$UNIT_PATH.new" && mv -f -- "$UNIT_PATH.new" "$UNIT_PATH"

if ! systemctl daemon-reload >/dev/null || ! systemctl enable --now gbf-gateway.service >/dev/null || ! systemctl restart gbf-gateway.service; then
  for pair in \
    "$BIN_PATH:binary" \
    "$CONFIG_DIR/config.json:config" \
    "$CONFIG_DIR/rules.json:rules" \
    "$UNIT_PATH:unit"; do
    target=${pair%%:*}; name=${pair##*:}
    if [ -e "$backup/$name.absent" ]; then rm -f -- "$target"; else cp -a -- "$backup/$name" "$target"; fi
  done
  systemctl daemon-reload >/dev/null || true
  systemctl try-restart gbf-gateway.service >/dev/null || true
  echo "gateway installation failed; previous service files restored" >&2
  exit 1
fi

printf 'HOST_PUBLIC_KEY=%s\n' "$(ssh-keygen -y -f "$host_key")"
printf 'NODE_PUBLIC_KEY=%s\n' "$(ssh-keygen -y -f "$node_key")"
