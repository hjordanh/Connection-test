# Connection Monitor

A lightweight, self-hosted internet connection monitor with a live web dashboard. Runs in the background and continuously tracks your connection health — no cloud accounts, no telemetry, no subscriptions.

![Dashboard showing ping chart, speed history, and site status tiles](https://placeholder)

---

## What it does

- **Connectivity monitoring** — checks your connection every 2 seconds and logs every outage with start time, end time, and duration
- **Live ping chart** — rolling 5-minute and 24-hour ping history with split view
- **Speed tests** — automatic download/upload measurements on startup, after outages, and on a periodic schedule; results compared against your hourly baseline so the most recent test is color-coded green/yellow/red
- **Site status tiles** — monitors named services (Netflix, Xbox Live, Fortnite, etc.) individually and shows a plain-English verdict (GREAT / OK / SLOW / DOWN) with trend arrows
- **Provider tracking** — detects which ISP or network you're on and tracks per-provider uptime and speed averages
- **Persistent storage** — history survives restarts; keeps 24 hours of ping data and speed results on disk

Everything is visible at **http://localhost:8765** in any browser on the same machine.

---

## Why it's helpful

Most people only notice their internet is bad when something breaks. This monitor runs quietly in the background and gives you:

- Proof of intermittent outages (exact times, durations) — useful when calling your ISP
- Early warning when a specific service (Xbox Live, a streaming service) is degraded before you blame your own connection
- A baseline sense of whether your speeds are normal for your connection
- Jitter and latency trends that explain why video calls feel choppy even when "the internet is working"

---

## Requirements

- **Python 3.8+**
- **Flask** — installed automatically on first run
- **speedtest-cli** *(optional)* — provides more accurate speed measurements than the built-in HTTP fallback

---

## Installation & Setup

### 1. Clone or download

```bash
git clone https://github.com/yourname/connection-monitor.git
cd connection-monitor
```

Or just download `connection_monitor.py` and `ping_targets.conf` into a folder.

### 2. Install optional dependencies

Flask installs itself automatically. For better speed tests, also install speedtest-cli:

```bash
pip3 install speedtest-cli
```

### 3. Configure monitored sites *(optional)*

Edit `ping_targets.conf` — one hostname per line. Lines starting with `#` are ignored.

```
# Streaming
netflix.com
disneyplus.com

# Gaming
xboxlive.com
epicgames.com
```

The file is read at startup. If it doesn't exist, a default set is created automatically.

### 4. Run it

```bash
python3 connection_monitor.py
```

Open **http://localhost:8765** in your browser. Press `Ctrl+C` to stop.

---

## Keeping it running persistently

### macOS — launchd (recommended)

Create a launch agent that starts on login and restarts if it crashes.

1. Create the plist file:

```bash
mkdir -p ~/Library/LaunchAgents
```

Save the following to `~/Library/LaunchAgents/com.user.connectionmonitor.plist`, replacing `/Users/yourname/connection-monitor` with your actual path:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.connectionmonitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/Users/yourname/connection-monitor/connection_monitor.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/Users/yourname/connection-monitor</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/connection_monitor.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/connection_monitor.err</string>
</dict>
</plist>
```

2. Load it:

```bash
launchctl load ~/Library/LaunchAgents/com.user.connectionmonitor.plist
```

3. Useful commands:

```bash
# Stop
launchctl unload ~/Library/LaunchAgents/com.user.connectionmonitor.plist

# Start
launchctl load ~/Library/LaunchAgents/com.user.connectionmonitor.plist

# Check if running
launchctl list | grep connectionmonitor

# View logs
tail -f /tmp/connection_monitor.log
```

---

### Linux — systemd (recommended)

1. Create the service file:

```bash
sudo nano /etc/systemd/system/connection-monitor.service
```

```ini
[Unit]
Description=Connection Monitor
After=network.target

[Service]
Type=simple
User=yourname
WorkingDirectory=/home/yourname/connection-monitor
ExecStart=/usr/bin/python3 /home/yourname/connection-monitor/connection_monitor.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Replace `yourname` and the paths with your actual username and install location.

2. Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable connection-monitor
sudo systemctl start connection-monitor
```

3. Useful commands:

```bash
# Check status
sudo systemctl status connection-monitor

# View live logs
sudo journalctl -u connection-monitor -f

# Stop
sudo systemctl stop connection-monitor

# Restart
sudo systemctl restart connection-monitor
```

---

### Windows — Task Scheduler

1. Open **Task Scheduler** (search for it in the Start menu)
2. Click **Create Basic Task** in the right panel
3. Fill in:
   - **Name**: Connection Monitor
   - **Trigger**: When I log on
   - **Action**: Start a program
   - **Program**: `pythonw.exe` *(runs without a console window)*
   - **Arguments**: `C:\path\to\connection_monitor.py`
   - **Start in**: `C:\path\to\` *(the folder containing the script)*
4. Check **Open the Properties dialog** before finishing, then enable **Run whether user is logged on or not** if you want it running even when your screen is locked

To find where `pythonw.exe` lives:
```cmd
where pythonw
```

**Alternative — NSSM (Non-Sucking Service Manager)**

For a proper Windows service that survives reboots without requiring a login:

1. Download [nssm](https://nssm.cc/download) and place `nssm.exe` somewhere in your PATH
2. From an Administrator command prompt:

```cmd
nssm install ConnectionMonitor
```

Fill in the GUI that appears:
- **Path**: path to `pythonw.exe`
- **Startup directory**: your project folder
- **Arguments**: `connection_monitor.py`

```cmd
nssm start ConnectionMonitor
```

---

## Accessing from other devices on your network

By default the dashboard only listens on localhost. To access it from your phone or another computer on the same Wi-Fi, find your machine's local IP:

- **macOS/Linux**: `ip addr` or `ifconfig`
- **Windows**: `ipconfig`

Then open `http://192.168.x.x:8765` on the other device. No code changes needed — Flask will accept connections on all interfaces as long as your firewall allows port 8765.

> **Note:** This is only for local network access. Do not expose port 8765 to the public internet without adding authentication.

---

## Data & privacy

- All data stays on your machine — nothing is sent anywhere
- History is saved to `connection_monitor_data.json` in the same folder as the script
- Speed tests make outbound HTTP requests to public test servers (Cloudflare, OVH, Tele2) to measure throughput
- Site monitoring makes TCP connection attempts to the hostnames in `ping_targets.conf`

---

## Troubleshooting

**Dashboard doesn't load**
- Make sure the script is still running (`Ctrl+C` stops it)
- Check that nothing else is using port 8765: `lsof -i :8765` (macOS/Linux) or `netstat -ano | findstr 8765` (Windows)

**Speed tests are slow or fail**
- Install `speedtest-cli` for more reliable results: `pip3 install speedtest-cli`
- The built-in HTTP fallback requires downloading ~10MB per test; it will fail on very slow or metered connections

**"Waiting for first site check…" stays forever**
- The site check runs a few seconds after startup — give it 10–15 seconds
- If a site shows DOWN immediately, check that the hostname in `ping_targets.conf` is correct and reachable on port 443

**Flask not found**
- The script attempts to auto-install Flask; if that fails, install it manually: `pip3 install flask`
