#!/usr/bin/env bash
set -euo pipefail
umask 077

# 本脚本仅用于自建的、经授权的专用游戏转发服务。不得用于经营 VPN、公共代理或绕过访问控制。
SERVICE_USER=gbf-control
SERVICE_GROUP=gbf-control
STATE_DIR=/var/lib/gbf-power/control
CONFIG_DIR=/etc/gbf-power/control
LIB_DIR=/usr/local/lib/gbf-power
BIN_PATH="$LIB_DIR/gbf-activation"
UNIT_PATH=/etc/systemd/system/gbf-control.service
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
UNIT_SOURCE="$SCRIPT_DIR/../systemd/gbf-control.service"

usage() {
  echo "usage: $0 --binary FILE --config FILE --tls-cert FILE --tls-key FILE [--metering-rules FILE]" >&2
  exit 2
}

binary_source=
config_source=
cert_source=
key_source=
metering_rules=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary) [ "$#" -ge 2 ] || usage; binary_source=$2; shift 2 ;;
    --config) [ "$#" -ge 2 ] || usage; config_source=$2; shift 2 ;;
    --tls-cert) [ "$#" -ge 2 ] || usage; cert_source=$2; shift 2 ;;
    --tls-key) [ "$#" -ge 2 ] || usage; key_source=$2; shift 2 ;;
    --metering-rules) [ "$#" -ge 2 ] || usage; metering_rules=$2; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$binary_source" ] && [ -n "$config_source" ] && [ -n "$cert_source" ] && [ -n "$key_source" ] || usage
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

canonical_file() {
  resolved=$(readlink -f -- "$1")
  [ -f "$resolved" ] && [ ! -L "$1" ] || { echo "input must be a regular, non-symlink file: $1" >&2; exit 1; }
  printf '%s\n' "$resolved"
}
binary_source=$(canonical_file "$binary_source")
config_source=$(canonical_file "$config_source")
cert_source=$(canonical_file "$cert_source")
key_source=$(canonical_file "$key_source")
[ -z "$metering_rules" ] || metering_rules=$(canonical_file "$metering_rules")
unit_source=$(canonical_file "$UNIT_SOURCE")

getent group "$SERVICE_GROUP" >/dev/null || groupadd --system "$SERVICE_GROUP"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --gid "$SERVICE_GROUP" --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -o root -g root -m 0755 "$LIB_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$STATE_DIR" "$CONFIG_DIR"

metering_key="$CONFIG_DIR/metering_host_ed25519"
if [ ! -e "$metering_key" ]; then
  runuser -u "$SERVICE_USER" -- ssh-keygen -q -t ed25519 -N '' -C gbf-control-gateway -f "$metering_key"
fi
chown "$SERVICE_USER:$SERVICE_GROUP" "$metering_key" "$metering_key.pub"
chmod 0600 "$metering_key"
chmod 0644 "$metering_key.pub"
primary_public=$(ssh-keygen -y -f "$metering_key")

stage=$(mktemp -d "$LIB_DIR/.control-stage.XXXXXX")
cleanup() { rm -rf -- "$stage"; }
trap cleanup EXIT INT TERM
install -m 0755 "$binary_source" "$stage/gbf-activation"
sed -e 's|${PRIMARY_NODE_HOST_PUBLIC_KEY}|'"$primary_public"'|g' "$config_source" >"$stage/config.json"
if grep -Eq '\$\{[A-Z0-9_]+\}' "$stage/config.json"; then
  echo "unresolved control configuration placeholder" >&2
  exit 1
fi
chown "$SERVICE_USER:$SERVICE_GROUP" "$stage/config.json"
chmod 0600 "$stage/config.json"
install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0644 "$cert_source" "$stage/tls.crt"
install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0600 "$key_source" "$stage/tls.key"
[ -z "$metering_rules" ] || install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0644 "$metering_rules" "$stage/rules.json"
install -m 0644 "$unit_source" "$stage/gbf-control.service"

# Offline validation performs strict JSON/schema checks and must not create state or bind a port.
"$stage/gbf-activation" check-config --config "$stage/config.json"

backup="$stage/backup"
install -d -m 0700 "$backup"
for pair in \
  "$BIN_PATH:binary" \
  "$CONFIG_DIR/config.json:config" \
  "$CONFIG_DIR/tls.crt:cert" \
  "$CONFIG_DIR/tls.key:key" \
  "$CONFIG_DIR/rules.json:rules" \
  "$UNIT_PATH:unit"; do
  target=${pair%%:*}; name=${pair##*:}
  if [ -e "$target" ]; then cp -a -- "$target" "$backup/$name"; else : >"$backup/$name.absent"; fi
done

install -m 0755 "$stage/gbf-activation" "$BIN_PATH.new"
mv -f -- "$BIN_PATH.new" "$BIN_PATH"
install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0600 "$stage/config.json" "$CONFIG_DIR/config.json.new"
mv -f -- "$CONFIG_DIR/config.json.new" "$CONFIG_DIR/config.json"
install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0644 "$stage/tls.crt" "$CONFIG_DIR/tls.crt.new"
mv -f -- "$CONFIG_DIR/tls.crt.new" "$CONFIG_DIR/tls.crt"
install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0600 "$stage/tls.key" "$CONFIG_DIR/tls.key.new"
mv -f -- "$CONFIG_DIR/tls.key.new" "$CONFIG_DIR/tls.key"
if [ -e "$stage/rules.json" ]; then
  install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0644 "$stage/rules.json" "$CONFIG_DIR/rules.json.new"
  mv -f -- "$CONFIG_DIR/rules.json.new" "$CONFIG_DIR/rules.json"
fi
install -m 0644 "$stage/gbf-control.service" "$UNIT_PATH.new"
mv -f -- "$UNIT_PATH.new" "$UNIT_PATH"

if ! systemctl daemon-reload || ! systemctl enable --now gbf-control.service || ! systemctl restart gbf-control.service; then
  for pair in \
    "$BIN_PATH:binary" \
    "$CONFIG_DIR/config.json:config" \
    "$CONFIG_DIR/tls.crt:cert" \
    "$CONFIG_DIR/tls.key:key" \
    "$CONFIG_DIR/rules.json:rules" \
    "$UNIT_PATH:unit"; do
    target=${pair%%:*}; name=${pair##*:}
    if [ -e "$backup/$name.absent" ]; then rm -f -- "$target"; else cp -a -- "$backup/$name" "$target"; fi
  done
  systemctl daemon-reload || true
  systemctl try-restart gbf-control.service || true
  echo "installation failed; previous files restored" >&2
  exit 1
fi

echo "control service installed; state in $STATE_DIR was preserved"
