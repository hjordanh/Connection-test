# VPS Deployment Guide

This guide covers setting up a central VPS to aggregate data from one or more local Connection Monitor instances. After completing this setup you'll have:

- A password-protected HTTPS dashboard accessible from anywhere
- Data from multiple home networks in a single view with a host selector
- The VPS's own ping as a "control" baseline (distinguishes "my network is bad" from "internet is bad")
- Automatic 30-day history migration from each local machine on its first sync

**You do not need to touch any local machine until the VPS is fully running.** Local monitoring continues uninterrupted throughout.

---

## Table of contents

1. [Choose a VPS](#1-choose-a-vps)
2. [Initial server setup](#2-initial-server-setup)
3. [Point a domain at your VPS](#3-point-a-domain-at-your-vps-recommended)
4. [Install the application](#4-install-the-application)
5. [Configure the application](#5-configure-the-application)
6. [Create the systemd service](#6-create-the-systemd-service)
7. [Install nginx and get an SSL certificate](#7-install-nginx-and-get-an-ssl-certificate)
8. [Harden the firewall](#8-harden-the-firewall)
9. [Verify the VPS is working](#9-verify-the-vps-is-working)
10. [Configure local collectors](#10-configure-local-collectors)
11. [Historical data migration](#11-historical-data-migration)
12. [Verify sync is running](#12-verify-sync-is-running)
13. [Security notes](#13-security-notes)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Choose a VPS

Any cheap Linux VPS works. Minimum specs: **1 vCPU, 512 MB RAM, 10 GB disk, Ubuntu 22.04 or 24.04 LTS, Python 3.10+.**

| Provider | Plan | Price | Notes |
|---|---|---|---|
| **Hetzner** | CX22 | ~$4/mo | Best value; EU and US data centers; easy setup |
| **Oracle Cloud** | Ampere A1 | Free (always-free tier) | 4 vCPUs, 24 GB RAM; best deal if you're patient with signup |
| **DigitalOcean** | Basic Droplet | $6/mo | Excellent documentation; familiar to many |
| **Vultr** | Cloud Compute | $5/mo | Many data center locations |

When creating the VPS, select **Ubuntu 24.04 LTS** and add your SSH public key during provisioning. Note the public IP address.

---

## 2. Initial server setup

SSH into your new VPS:

```bash
ssh root@YOUR_VPS_IP
```

Update the system and install required packages:

```bash
apt update && apt upgrade -y
apt install -y python3 python3-pip git nginx certbot python3-certbot-nginx ufw
```

Create a dedicated non-root user to run the application:

```bash
adduser monitor          # set a password when prompted
usermod -aG sudo monitor
```

---

## 3. Point a domain at your VPS (recommended)

HTTPS requires a domain name. In your DNS provider's control panel, create an **A record**:

```
Type:  A
Name:  monitor          (or whatever subdomain you want)
Value: YOUR_VPS_IP
TTL:   300
```

This makes `monitor.yourdomain.com` point at your VPS. DNS propagation usually takes a few minutes.

> **No domain?** You can skip HTTPS and run on a plain IP (`http://YOUR_VPS_IP:8080`). Skip steps 3 and 7 and skip `DASHBOARD_USER`/`DASHBOARD_PASS` (the endpoint will be unprotected on the open internet — use it only for testing, not long-term).

---

## 4. Install the application

Switch to the monitor user and clone the repo:

```bash
su - monitor
git clone https://github.com/hjordanh/Connection-test.git /home/monitor/connection-monitor
cd /home/monitor/connection-monitor
```

---

## 5. Configure the application

Generate a random API key (you'll need this on both the VPS and every local machine):

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy the example config and fill in values:

```bash
cp connection_monitor.env.example connection_monitor.env
nano connection_monitor.env
```

Set these values in `connection_monitor.env`:

```bash
# Shared secret — paste the key you generated above
INGEST_API_KEY=<your-generated-key>

# Dashboard login (protects the web UI from public access)
DASHBOARD_USER=admin
DASHBOARD_PASS=<pick a strong password>

# VPS-specific settings
DISABLE_SPEED_TESTS=true    # avoids bandwidth charges
AGGREGATOR=true             # enables multi-host view

# Optional: enable AI diagnosis on the VPS
ANTHROPIC_API_KEY=<your key>

# Flask listens on this port internally (nginx proxies in from 443)
PORT=8080
```

Leave everything else at defaults. Save and exit.

---

## 6. Create the systemd service

Create the service file as root:

```bash
exit   # back to root
sudo nano /etc/systemd/system/connection-monitor.service
```

Paste this content (adjust paths if you used a different username):

```ini
[Unit]
Description=Connection Monitor (VPS Aggregator)
After=network.target

[Service]
Type=simple
User=monitor
WorkingDirectory=/home/monitor/connection-monitor
EnvironmentFile=/home/monitor/connection-monitor/connection_monitor.env
ExecStart=/usr/bin/python3 /home/monitor/connection-monitor/connection_monitor.py
Restart=always
RestartSec=5
StandardOutput=append:/home/monitor/connection-monitor/var/monitor.out.log
StandardError=append:/home/monitor/connection-monitor/var/monitor.err.log

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now connection-monitor
```

Check it started:

```bash
sudo systemctl status connection-monitor
# Should show "Active: active (running)"
```

If Flask auto-installation fails on first start, install dependencies manually:

```bash
sudo -u monitor pip3 install flask python-dotenv
sudo systemctl restart connection-monitor
```

---

## 7. Install nginx and get an SSL certificate

Create an nginx site config:

```bash
sudo nano /etc/nginx/sites-available/connection-monitor
```

Paste:

```nginx
server {
    listen 80;
    server_name monitor.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # The /api/ingest endpoint receives up to 30 days of ping data.
        # Flask compresses the response, but the request body can be large.
        client_max_body_size 64m;
    }
}
```

Enable it and obtain the SSL certificate:

```bash
sudo ln -s /etc/nginx/sites-available/connection-monitor /etc/nginx/sites-enabled/
sudo nginx -t                  # verify config is valid
sudo systemctl reload nginx

# Get the certificate (certbot modifies the nginx config to add HTTPS)
sudo certbot --nginx -d monitor.yourdomain.com
```

Certbot will prompt for your email (for renewal reminders) and ask whether to redirect HTTP→HTTPS — choose yes.

Verify auto-renewal works:

```bash
sudo certbot renew --dry-run
```

---

## 8. Harden the firewall

Allow only SSH, HTTP (for certbot challenges), and HTTPS. Keep port 8080 (Flask) internal:

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status
```

**Do not open port 8080.** Flask should only be reachable through nginx.

---

## 9. Verify the VPS is working

Open `https://monitor.yourdomain.com` in a browser. You should see a login prompt, and after entering your dashboard credentials, the Connection Monitor dashboard showing the VPS's own ping data.

Test the ingest API endpoint directly:

```bash
curl -s -X POST https://monitor.yourdomain.com/api/ingest \
  -H "Authorization: Bearer YOUR_INGEST_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"monitor_host":"test-probe","ping_ts":[],"access_ts":[],"speed_samples":[],"outages":[],"degraded":[],"site_ping_history":{},"network_uptime":{},"network_colors":{},"daily_history":[],"router_events":[],"dismissed_outage_ids":[]}' \
| python3 -m json.tool
```

You should see `{"ok": true}`. If you get `401 Unauthorized`, the key doesn't match what's in the VPS's `connection_monitor.env`.

---

## 10. Configure local collectors

On each home machine, add these lines to `connection_monitor.env`:

```bash
SERVER_URL=https://monitor.yourdomain.com
INGEST_API_KEY=<same key as the VPS>

# Optional: a descriptive name for this machine on the VPS dashboard.
# Defaults to the system hostname if not set.
MONITOR_HOST=jordans-macbook-wifi-a
```

Restart the local monitor:

```bash
# macOS launchd
launchctl stop com.jordan.connectionmonitor

# Linux systemd
sudo systemctl restart connection-monitor
```

The sync thread starts 90 seconds after the monitor starts (to let local state warm up), then pushes every 60 seconds. You don't need to do anything else.

---

## 11. Historical data migration

**No manual migration step is needed.** On the first sync after adding `SERVER_URL`, the local monitor sends its full in-memory state — up to 30 days of ping, speed, site, outage, degraded, and router data — to the VPS in a single POST. The VPS uses `INSERT OR IGNORE` to deduplicate, so re-sending on subsequent syncs is safe.

If your local retention windows are longer than the defaults (e.g., you've increased `RETAIN_PINGS_DAYS`), data beyond what's in memory at startup won't sync automatically. In that case you can copy the SQLite file directly:

```bash
# On your local machine — stop the VPS service first, then:
scp var/connection_monitor.db monitor@YOUR_VPS_IP:/home/monitor/connection-monitor/var/connection_monitor.db

# Restart the VPS service
ssh monitor@YOUR_VPS_IP 'sudo systemctl restart connection-monitor'
```

The VPS will load all host data from the copied file on startup. Subsequent syncs from local machines are still deduped via `INSERT OR IGNORE`.

### Adding a second machine

Repeat step 10 on the second machine with a different `MONITOR_HOST` value. Its data appears as a separate entry in the VPS host selector within 2 minutes of its first sync.

---

## 12. Verify sync is running

On the local machine, watch the log for sync confirmations:

```bash
tail -f var/monitor.out.log | grep sync
# Expected: [2026-06-29 22:00:00]  sync: pushed to https://monitor.yourdomain.com (jordans-macbook-wifi-a)
```

On the VPS, check which hosts have synced:

```bash
curl -s -u admin:YOUR_DASHBOARD_PASS \
  https://monitor.yourdomain.com/api/hosts \
| python3 -m json.tool
```

This returns each registered host with its `last_seen` timestamp.

---

## 13. Security notes

- **HTTPS is mandatory for production.** Sync traffic includes your network ping history and ISP performance data, which travels in plaintext over HTTP.
- **Keep port 8080 firewalled.** The dashboard's Basic Auth lives in Python — it's adequate behind nginx but not hardened for direct internet exposure.
- **Rotate `INGEST_API_KEY` if compromised.** Update it in `connection_monitor.env` on the VPS and every collector, then restart all instances. Old keys stop working immediately.
- **`DASHBOARD_USER`/`DASHBOARD_PASS` only protect the dashboard UI.** The `/api/ingest` endpoint uses a separate Bearer token and is intentionally excluded from Basic Auth so collectors can push data without browser credentials.
- **The VPS dashboard is read-only public.** Even with the password, the dashboard has no admin functions — the worst-case exposure from a leaked password is viewing your ping history.

---

## 14. Troubleshooting

**`sync: push to ... failed: HTTP Error 401: Unauthorized`**
The `INGEST_API_KEY` on the local machine doesn't match the VPS. Double-check both `connection_monitor.env` files and restart both services.

**`sync: push to ... failed: <URLError reason: [Errno 111] Connection refused>`**
The VPS service isn't running, or nginx isn't proxying correctly. SSH into the VPS and check:
```bash
sudo systemctl status connection-monitor
sudo systemctl status nginx
sudo journalctl -u connection-monitor -n 50
```

**`sync: push to ... failed: SSL: CERTIFICATE_VERIFY_FAILED`**
The SSL certificate isn't trusted (e.g., self-signed or certbot didn't finish). Re-run `sudo certbot --nginx -d monitor.yourdomain.com`.

**Dashboard loads but host selector only shows the VPS host**
The local machine hasn't synced yet (wait 90–150 seconds after restarting the local monitor) or `AGGREGATOR=true` isn't set on the VPS.

**`connection refused` trying to reach port 8765 from the VPS**
Local machines aren't reachable from the VPS — the push is outbound from local → VPS, not the other way around. This is expected behavior.

**VPS service fails to start with `Address already in use`**
Another process has port 8080. Check: `sudo lsof -i :8080`. Change `PORT=` in the VPS's `connection_monitor.env` to an available port and update the nginx `proxy_pass` line to match.

**nginx returns 502 Bad Gateway**
Flask isn't running. Check `sudo systemctl status connection-monitor` and look at `var/monitor.err.log` for startup errors.

**Certbot says `Challenge failed for domain ...`**
DNS hasn't propagated yet, or port 80 is blocked. Verify:
```bash
# DNS check
dig +short monitor.yourdomain.com

# Port 80 reachable (run from outside the VPS)
curl -v http://monitor.yourdomain.com
```
