# kasa2onvif

A from-scratch Go tool for a **TP-Link Kasa KD110 doorbell camera** that
exposes it as a standard **RTSP** stream and an **ONVIF device**, so
**UniFi Protect** can discover and adopt it. Built for Raspberry Pi 4
(64-bit), zero external dependencies (single static binary, no ffmpeg).

Everything is implemented directly against the reverse-engineered Kasa
protocol.

```
Kasa KD110 camera ──HTTPS/TLS (multipart)──> kasa2onvif ──RTSP (RTP/TCP)──> UniFi Protect
                                              │
                                              └─ONVIF device service (SOAP) + WS-Discovery─> adoption
```

## Layout

| Path | Purpose |
|------|---------|
| `cmd/kasa2onvif` | entry point |
| `internal/config` | YAML config (subset parser + tests) |
| `internal/kasa` | Kasa HTTPS/multipart client (chunked + HTTP/1.0 quirks, Basic auth ladder) |
| `internal/h264` | NAL splitter + SPS parser (profile/level/dimensions/fps) |
| `internal/source` | connection manager: reconnect, backoff, monotonic timestamp rebasing |
| `internal/hub` | keyframe-primed broadcast hub with per-consumer bounded queues |
| `internal/rtsp` | RTSP 1.0 server: DESCRIBE/SETUP/PLAY, Digest auth, RFC 6184 packetizer (STAP-A/FU-A), interleaved TCP |
| `internal/onvif` | ONVIF Device+Media service (SOAP), ws-username token auth, WS-Discovery responder |
| `internal/api` | status HTTP API |
| `internal/app` | wiring: SDP built from live SPS/PPS, combined HTTP listener |
| `deploy/` | systemd unit + installer |

## Design decisions (why the video is stable)

1. **Timestamps**: Kasa `X-Timestamp` values are wall-clock seconds that jump
   (and reset on camera reboot). Feeding jumps into RTP timestamps makes the
   client's jitter buffer stall -> frozen video. Here RTP timestamps come
   from the **local monotonic clock**, with camera timestamps used only to
   detect large drift (rebase on >1.5s backwards jump).
2. **Keyframe sync**: consumers that join mid-GOP would decode P-frames
   without SPS/PPS/IDR -> grey/frozen frames until the next GOP. The hub
   **primes every new consumer with the latest keyframe** and drops backlog
   for slow consumers (resync on next IDR).
3. **Session stability**: the single-producer design keeps one camera
   connection alive across consumers; consumers joining/leaving never reset
   the source.
4. **Backpressure**: the camera's multiplexed stream is consumed at its own
   pace; the RTSP writer never blocks the source (bounded queues + drop).

## Configuration

Copy the example and edit in your credentials:

```sh
cp config.example.yaml config.yaml
```

- `source.kasa`: `kasa://email%40domain:password@camera-host:19443/https/stream/mixed?video=h264&audio=g711&resolution=hd`
  - `email%40domain` is your Kasa account e-mail (`@` → `%40`), `password` the
    account password (the proxy base64-encodes it for you). The proxy tries,
    in order: e-mail + base64(password), e-mail + plain, admin + base64,
    admin + plain.
- `rtsp`: internal RTSP server (`:8554`, path `doorcam`, credentials that
  Protect will use on the stream).
- `onvif`: credentials Protect enters when adopting, device identity strings,
  optional `rtsp_host` (set it if the auto-detected IP is wrong).
- `discovery`: WS-Discovery UDP 3702 responder (`enabled: true`).
- `api`: HTTP status + ONVIF SOAP endpoint (shared `:8080`).

## Build & run (local)

```sh
make            # build native binary
make test       # run unit tests
./kasa2onvif -config config.yaml
```

## Deploy to the Pi (SSH target of your choice)

`SSH_USER`/`SSH_HOST` (defaults: `pi@raspberrypi.local`) - override with your
own:

```sh
make deploy SSH_USER=pi SSH_HOST=myrpi      # cross-compiles arm64, scps to $SSH_USER@$SSH_HOST
ssh <user>@<pi-host>
sudo ./install.sh                           # installs /usr/local/bin + systemd service
```

Ports used on the Pi: 8554/tcp (RTSP), 8080/tcp (API + ONVIF), 3702/udp
multicast socket for WS-Discovery (239.255.255.250:3702).

## Adopt in UniFi Protect

1. UniFi Protect → **Settings → System → Discover third-party cameras** → enable.
2. Go to the **UniFi Devices** page; the camera appears as
   *"Kasa Doorbell"* ready for adoption (WS-Discovery). If it doesn't show up,
   use the help icon → **Advanced Adoption** → enter the Pi's IP.
3. Enter the ONVIF credentials from your `config.yaml` (the `onvif.username`
   / `onvif.password` values you set).
4. After adoption Protect pulls the RTSP URI delivered via ONVIF
   `GetStreamUri` (with the credentials from the `rtsp:` config block).
5. Enable **audio** on the camera in Protect (G.711u gets transcoded).

> Note: Protect caches the stream profile at adoption time. If you change
> stream/layout settings, **remove and re-adopt** the camera.

### Camera functionality in Protect

- HQ/LQ come from the single advertised profile (KD110 main stream).
- Motion detection must come from the camera; this proxy doesn't generate
  motion events.

## Troubleshooting

```sh
curl http://<pi-host>:8080/api/status     # has_video, fps, connections
ffplay rtsp://<rtsp-user>:<rtsp-pass>@<pi-host>:8554/doorcam   # verify the stream directly
journalctl -u kasa2onvif -f           # service logs
```

If Protect can't adopt: enable `discovery.enabled`, check the two credentials
blocks (ONVIF creds for adoption, RTSP creds for the stream), and confirm the
Pi's firewall allows UDP 3702 + TCP 8554/8080.

## References

- <https://medium.com/@hu3vjeen/reverse-engineering-tp-link-kc100-bac4641bf1cd> - Kasa protocol
- <https://help.ui.com/hc/en-us/articles/26301104828439-Third-Party-Cameras-in-UniFi-Protect> - adoption flow
- <https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf> - ONVIF core spec
- <https://github.com/AlexxIT/go2rtc> - prior art for the Kasa protocol and a reference RTSP implementation
