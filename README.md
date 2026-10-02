# Telegram Group Virus Detection Bot

Automatically scans every file uploaded to a Telegram group with **ClamAV**,
deletes infected files, and never falsely reports a file as safe if the
scanner is unavailable.

## Features

- Scans PDFs, Office docs, archives, executables, APKs, images, text files —
anything sent as a Telegram document.
- Streams files to ClamAV in memory over the network (`INSTREAM`) — the bot
never keeps a permanent copy of an uploaded file.
- Configurable extension blocklist (`.exe`, `.bat`, `.cmd`, `.scr`, `.vbs`,
`.ps1`, `.msi`, `.jar`, `.apk`, `.com` by default).
- Configurable max file size, enforced **before** download.
- SQLite scan log + per-group settings (never file contents).
- `/stats` command with totals for safe / infected / failed / blocked scans.
- Clear "scan failed" messaging — the bot never claims a file is safe when it
can't actually verify that.
- Docker Compose setup with ClamAV running as its own container with
automatic signature updates (`freshclam`).



## Project structure

```
telegram-virus-bot/
├── bot.py              # Telegram handlers & main entry point
├── scanner.py          # ClamAV integration, filename sanitisation, temp files
├── database.py         # SQLite scan logs + per-group settings
├── config.py            # Environment-variable driven configuration
├── requirements.txt
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── README.md
└── data/                # SQLite DB lives here (created automatically)
```

---



## 1. Create the bot with BotFather

1. Open Telegram and start a chat with **@BotFather**.
2. Send `/newbot` and follow the prompts (choose a name, then a username
  ending in `bot`).
3. BotFather replies with an **API token** — copy it, you'll need it below.
4. Optional but recommended: send `/setprivacy` → choose your bot →
  This lets th**Disable** privacy mode. e bot see all messages/files in a
   group, not just ones addressed to it directly (required for automatic
   scanning to work).
5. Optional: `/setjoingroups` → Enable, so the bot can be added to groups.



## 2. Add the bot to your group as an administrator

1. Open the target group → **Group info → Administrators → Add Admin**.
2. Search for your bot's username and add it.
3. Grant at minimum:
  - **Delete messages** (required — this is how infected files get removed)
4. The bot does **not** need permissions to ban/restrict users, pin
  messages, etc. Grant only what it needs.

---



## 3. Local / manual installation



### Prerequisites

- Python 3.11+
- ClamAV (`clamd` daemon) installed and running, **or** use the Docker setup
below which handles this for you.



### Steps

```bash
git clone <this-repo-url> telegram-virus-bot
cd telegram-virus-bot

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env and set TELEGRAM_BOT_TOKEN (and CLAMAV_HOST/PORT if not using Docker)

# If running ClamAV locally (not in Docker), install it and start clamd:
#   sudo apt install clamav clamav-daemon
#   sudo systemctl enable --now clamav-daemon
#   sudo freshclam   # first signature download (systemd timer keeps it updated)
# Then set CLAMAV_HOST=127.0.0.1 (or your clamd socket's TCP address) in .env.
# Note: by default clamd listens on a local Unix socket. To use it over TCP,
# edit /etc/clamav/clamd.conf and set:
#   TCPSocket 3310
#   TCPAddr 127.0.0.1
# then restart: sudo systemctl restart clamav-daemon

python bot.py
```

---



## 4. Docker deployment (recommended)

This spins up ClamAV (with automatic signature updates) and the bot together.

```bash
cp .env.example .env
# edit .env and set TELEGRAM_BOT_TOKEN — leave CLAMAV_HOST=clamav (default)

docker compose up -d --build

# Watch logs
docker compose logs -f bot
```

The first ClamAV startup downloads the full signature database (a few
hundred MB), which can take a few minutes — the bot container waits for
ClamAV's healthcheck before starting (`depends_on: condition: service_healthy`).

To stop: `docker compose down` (add `-v` to also remove the ClamAV signature
volume, forcing a fresh download next time).

### Important: match ClamAV's stream size limit to your bot's max file size

ClamAV's `INSTREAM` command has its own size cap (`StreamMaxLength`,
default 25 MB) independent of the bot's own `DEFAULT_MAX_FILE_SIZE_MB`. If
you raise the bot's limit above 25 MB, also raise ClamAV's, e.g. by mounting
a custom `clamd.conf` with:

```
StreamMaxLength 100M
```

Otherwise large-but-under-your-limit files will scan as "error" (safely
refused, never falsely marked safe) rather than actually being scanned.

---



## 5. Ubuntu / Oracle Cloud (OCI) deployment

These steps work on a fresh Ubuntu 22.04/24.04 VM (e.g. an OCI "Always Free"
Ampere or VM.Standard instance).

```bash
# 1. Update the system
sudo apt update && sudo apt upgrade -y

# 2. Install Docker + Compose plugin
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# 3. Allow your user to run docker without sudo (log out/in after this)
sudo usermod -aG docker $USER

# 4. Clone the project and configure it
git clone <this-repo-url> telegram-virus-bot
cd telegram-virus-bot
cp .env.example .env
nano .env   # set TELEGRAM_BOT_TOKEN

# 5. Start it
docker compose up -d --build

# 6. Confirm it's healthy
docker compose ps
docker compose logs -f bot
```



### Oracle Cloud networking note

This bot only makes **outbound** connections to Telegram's servers (long
polling) — it does not need any inbound port opened in your OCI Security
List / Network Security Group or the Ubuntu firewall (`ufw`). Keep inbound
rules locked down to just SSH (port 22) unless you have another reason to
open ports.

### Keeping it running / auto-restart on reboot

`docker compose` containers use `restart: unless-stopped`, so they'll
survive reboots automatically once Docker's own service is enabled:

```bash
sudo systemctl enable docker
```

---



## 6. Configuration reference (`.env`)


| Variable                      | Default                   | Description                                                            |
| ----------------------------- | ------------------------- | ---------------------------------------------------------------------- |
| `TELEGRAM_BOT_TOKEN`          | *(required)*              | Token from BotFather. Never commit this.                               |
| `SUPER_ADMIN_IDS`             | *(empty)*                 | Comma-separated Telegram user IDs who can always use `/settings`.      |
| `CLAMAV_HOST` / `CLAMAV_PORT` | `clamav` / `3310`         | Where to reach the clamd daemon.                                       |
| `CLAMAV_TIMEOUT_SECONDS`      | `60`                      | Hard timeout for a single scan.                                        |
| `DEFAULT_MAX_FILE_SIZE_MB`    | `50`                      | Default per-group max file size (overridable via `/settings maxsize`). |
| `HARD_MAX_FILE_SIZE_MB`       | `200`                     | Absolute ceiling no group setting can exceed.                          |
| `TEMP_DIR`                    | `/tmp/telegram_virus_bot` | Scratch directory for downloads (always cleaned up).                   |
| `DB_PATH`                     | `data/bot.db`             | SQLite database location.                                              |




## 7. Bot commands


| Command     | Who                             | Description                                          |
| ----------- | ------------------------------- | ---------------------------------------------------- |
| `/start`    | anyone                          | Introduction                                         |
| `/help`     | anyone                          | Command list                                         |
| `/status`   | anyone                          | Bot uptime + whether ClamAV is currently reachable   |
| `/scan`     | anyone                          | Reply to a file message to manually (re)scan it      |
| `/stats`    | anyone                          | Scan statistics for the current chat                 |
| `/settings` | anyone (view) / admins (change) | View or change max file size and extension blocklist |




## 8. Security design notes

- **No hard-coded secrets.** The bot token is read only from the
environment (`.env`, which is git-ignored).
- **Path traversal / injection safety.** Uploaded filenames are never used
to build filesystem paths. Every temp file uses a random UUID name
generated by the bot; the original filename is only used, sanitised, for
display and logging.
- **No shell/subprocess calls with user input.** Scanning goes over a
ClamAV network protocol (`clamd`/`INSTREAM`) using the `clamd` Python
library — there is no `shell=True` or string-built command anywhere in
this project.
- **Fail closed, not open.** Any ClamAV connection error, timeout, or
unexpected response is treated as `ERROR`, which is always reported to
the group as "unable to verify" — never as "safe". A file is only ever
marked safe on an explicit ClamAV `OK` response.
- **Size-gated downloads.** File size (reported by Telegram in the message
metadata) is checked *before* the bot downloads anything, so oversized
files never touch disk or memory.
- **Least privilege.** The bot only needs "delete messages" admin rights in
the group — nothing else. The Docker image runs as a non-root user.
- **No data retention beyond what's needed.** Uploaded file bytes are
written to a temp file, scanned, and deleted immediately afterward
(`finally` block guarantees cleanup even on error). The SQLite log stores
only metadata (filename, size, result, detection name) — never file
contents.
- **Timeouts everywhere.** Both the ClamAV client library timeout and an
outer `asyncio.wait_for` guard bound how long a single scan can run, so a
hung ClamAV daemon can't stall the bot.



## 9. Limitations to be aware of

- Telegram's **compressed photos** (sent as regular photos, not "Send as
file") are recompressed by Telegram itself and are not scanned by this
bot — only files sent as *documents* trigger a scan. Advise users to send
images "as a file" if you want them scanned.
- ClamAV signature-based detection does not catch 100% of malware,
especially novel or heavily obfuscated threats. Treat this bot as one
layer of defence, not a complete guarantee.
- If the bot loses its "delete message" permission, infected files will be
flagged in chat but not automatically removed — `/status` and the alert
message will say so explicitly.

