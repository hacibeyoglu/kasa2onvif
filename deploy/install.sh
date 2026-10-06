#!/bin/sh
# Install kasa2onvif as a systemd service on the Raspberry Pi.
# Run on the Pi:  sudo ./install.sh
set -e

SERVICE=kasa2onvif
BIN=/usr/local/bin/kasa2onvif
CONF=/etc/kasa2onvif/config.yaml
UNIT=/etc/systemd/system/${SERVICE}.service

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }

install -m 0755 kasa2onvif "$BIN"
mkdir -p /etc/kasa2onvif
[ -f "$CONF" ] || install -m 0644 config.yaml "$CONF"

cat > "$UNIT" <<EOF
[Unit]
Description=Kasa Doorbell RTSP/ONVIF proxy (kasa2onvif)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN -config $CONF
Restart=always
RestartSec=5
Nice=-5
LimitNOFILE=8192
NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE"
echo "Installed. Status:"
systemctl --no-pager status "$SERVICE" | head -12
echo
echo "Logs:    journalctl -u $SERVICE -f"
echo "Status:  curl http://localhost:8080/api/status"
