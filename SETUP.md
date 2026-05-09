# PQC Secure Chat + Encrypted File Share

**Project by Het Patel**
Post-Quantum Cryptography based secure chat and file sharing system.

---

## Crypto Stack

| Layer | Algorithm | Standard | Purpose |
|-------|-----------|----------|---------|
| Identity | ML-DSA-65 | NIST FIPS 204 | Digital signatures — proves who you are |
| Key Exchange | ML-KEM-768 | NIST FIPS 203 | Key encapsulation — replaces ECDH |
| Forward Secrecy | Double Ratchet | Signal Protocol | Per-message + per-chunk key rotation |
| Encryption | AES-256-GCM | NIST SP 800-38D | Chat messages + every file chunk |
| Authentication | KMAC-256 | NIST SP 800-185 | MAC on every message and file chunk |

**Server:** Pure relay — cannot decrypt anything. Stores only metadata.

---

## File Structure

```
pqc_chat/
├── .env                   ← server config (NOT uploaded to GitHub)
├── .gitignore             ← excludes .env, venv, db, __pycache__
├── requirements.txt       ← server dependencies
├── SETUP.md               ← this file
├── server/
│   ├── main.py            ← FastAPI WebSocket relay server
│   ├── database.py        ← SQLite async — chat log + file metadata
│   └── crypto.py          ← all PQC crypto
└── client/
    ├── client.py          ← terminal client
    └── requirements.txt   ← client-only dependencies
```

---

## IMPORTANT — Two Separate Requirements Files

| File | Used by | Contains |
|------|---------|---------|
| `requirements.txt` (root) | Server machine | FastAPI + uvicorn + all crypto libs + aiosqlite |
| `client/requirements.txt` | Client machines | websockets + crypto libs only (no FastAPI/uvicorn/aiosqlite) |

Client machines do NOT need FastAPI, uvicorn, or aiosqlite.

---

## SERVER SETUP

### Step 1 — Clone / Download Project

```bash
git clone https://github.com/YOUR_USERNAME/pqc_chat.git
cd pqc_chat
```

### Step 2 — Create .env File (NOT in GitHub — create manually)

Create a file named `.env` in the root folder:
```
HOST=0.0.0.0
PORT=8000
DB_PATH=chat.db
LOG_LEVEL=INFO
```

### Step 3 — Install Server Dependencies

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> If PowerShell gives execution policy error:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

### Step 4 — Run Server

**Linux / macOS:**
```bash
source venv/bin/activate
python server/main.py
```

**Windows (PowerShell):**
```powershell
.\venv\Scripts\Activate.ps1
python server\main.py
```

Server starts and shows PQC self-test:
```
✅ ALL CHECKS PASSED — algorithms verified against FIPS specs
🚀 PQC Chat + Encrypted File Relay Server started
Uvicorn running on http://0.0.0.0:8000
```

### Step 5 — Find Server IP

**Linux:**
```bash
ip a
# Look for inet 192.168.x.x under eth0 or ens33
```

**Windows:**
```powershell
ipconfig
# Look for IPv4 Address under your network adapter
```

Note this IP — all clients need it. Example: `192.168.1.50`

### Step 6 — Open Firewall Port 8000

**Linux:**
```bash
sudo ufw allow 8000
sudo ufw reload
```

**Windows (Run PowerShell as Administrator):**
```powershell
netsh advfirewall firewall add rule name="PQC Chat 8000" dir=in action=allow protocol=TCP localport=8000
```

---

## CLIENT SETUP (Every Client Machine)

Client needs only 3 files:
```
anywhere_on_client/
├── client.py          ← copy from client/ folder
├── crypto.py          ← copy from server/ folder (client imports this)
└── requirements.txt   ← copy from client/requirements.txt
```

### Step 1 — Install Client Dependencies

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> **Windows — If you have Anaconda installed:**
> Make sure you use venv python, NOT Anaconda python.
> After activating venv, verify:
> ```powershell
> where.exe python
> # Must show: C:\...\venv\Scripts\python.exe
> # NOT: C:\Anaconda\...
> ```

### Step 2 — Run Client

**Linux / macOS — Server on same machine:**
```bash
source venv/bin/activate
python client.py --username alice
```

**Linux / macOS — Server on different machine:**
```bash
source venv/bin/activate
python client.py --username alice --server ws://192.168.1.50:8000
```

**Windows — Server on same machine:**
```powershell
.\venv\Scripts\Activate.ps1
python client.py --username alice --server ws://localhost:8000
```

**Windows — Server on different machine (Linux/other Windows):**
```powershell
.\venv\Scripts\Activate.ps1
python client.py --username alice --server ws://192.168.1.50:8000
```

> **Windows Note:** Always provide `--server` flag explicitly on Windows.
> `ws://localhost:8000` if server is on same Windows machine.
> `ws://SERVER_IP:8000` if server is on another machine.

---

## RUNNING SCENARIOS

### Scenario A — Everything on Same Machine (Same OS)

Open 3 terminals:

**Terminal 1 — Server:**
```bash
# Linux
source venv/bin/activate && python server/main.py

# Windows
.\venv\Scripts\Activate.ps1; python server\main.py
```

**Terminal 2 — Alice:**
```bash
# Linux
python client/client.py --username alice

# Windows
python client\client.py --username alice --server ws://localhost:8000
```

**Terminal 3 — Bob:**
```bash
# Linux
python client/client.py --username bob

# Windows
python client\client.py --username bob --server ws://localhost:8000
```

---

### Scenario B — Server on Linux, Clients on Windows

**Linux machine — Run server:**
```bash
source venv/bin/activate
python server/main.py
ip a   # note IP, e.g. 192.168.1.50
sudo ufw allow 8000
```

**Windows machine — Run client:**
```powershell
.\venv\Scripts\Activate.ps1
python client.py --username alice --server ws://192.168.1.50:8000
```

---

### Scenario C — Server on Windows, Clients on Linux/Windows

**Windows machine — Run server (PowerShell as Admin for firewall):**
```powershell
.\venv\Scripts\Activate.ps1
python server\main.py
ipconfig   # note IPv4 address e.g. 192.168.1.100
# Open firewall (run as admin):
netsh advfirewall firewall add rule name="PQC Chat 8000" dir=in action=allow protocol=TCP localport=8000
```

**Linux client:**
```bash
python3 client.py --username bob --server ws://192.168.1.100:8000
```

**Another Windows client:**
```powershell
python client.py --username carol --server ws://192.168.1.100:8000
```

---

### Scenario D — Multiple Clients Same Machine Different Usernames

Fully supported — open as many terminals as needed:
```powershell
# Terminal 1
python client.py --username alice --server ws://SERVER_IP:8000

# Terminal 2
python client.py --username bob --server ws://SERVER_IP:8000

# Terminal 3
python client.py --username carol --server ws://SERVER_IP:8000
```
Each is independent. Server sees them as separate users.

---

## HOW TO USE — Complete Example

### Step 1 — Find who is online
```
/users
/search bob
```

### Step 2 — Establish encrypted session (REQUIRED before chat or file send)
```
/session bob
```
Both sides must be online. Alice initiates, Bob auto-confirms.
```
Alice sees: [🔐 'bob' confirmed — session ready]
Bob sees:   [🔐 Session with 'alice' established]
```

### Step 3 — Send encrypted messages
```
/msg bob Hello! This is end-to-end encrypted with AES-256-GCM.
```
Every message uses a fresh ratchet key. Server cannot read any of this.

### Step 4 — Send encrypted file
```
/send bob C:\Users\Het\Documents\report.pdf        # Windows
/send bob /home/het/documents/report.pdf           # Linux
```
File auto-accepted on Bob's side if session active + disk space OK.
Progress shown on both sides with speed and ETA.
File saved to `~/securechatfiles/` on Bob's machine.

### Step 5 — View transfer history
```
/transfers
```

### Step 6 — Exit
```
/quit
```

---

## FILE SAVE LOCATIONS

Received files are saved automatically to:

| OS | Path |
|----|------|
| Windows | `C:\Users\<username>\securechatfiles\` |
| Linux | `/home/<username>/securechatfiles/` |
| macOS | `/Users/<username>/securechatfiles/` |

Folder is created automatically on first run.
Duplicate filenames get suffix: `file_1.pdf`, `file_2.pdf` etc.

---

## COMMANDS REFERENCE

| Command | Description |
|---------|-------------|
| `/users` | List all currently online users |
| `/search <user>` | Check if user exists and is online |
| `/session <user>` | Establish PQC encrypted session — required before /msg and /send |
| `/msg <user> <text>` | Send AES-256-GCM encrypted message |
| `/send <user> <filepath>` | Send encrypted file — auto-accepted on receiver side |
| `/transfers` | Show session file transfer history |
| `/quit` | Exit |

---

## REST API — Admin / Debug

```bash
# Health check — online users and active transfers
curl http://SERVER_IP:8000/health

# All chat messages
curl http://SERVER_IP:8000/messages

# Conversation between two users
curl http://SERVER_IP:8000/history/alice/bob

# All file transfer records
curl http://SERVER_IP:8000/transfers

# Transfers for specific user
curl http://SERVER_IP:8000/transfers/alice
```

---

## TROUBLESHOOTING

**Windows — TimeoutError on client connect**
→ Always use `--server ws://SERVER_IP:8000` on Windows
→ If server is on same Windows machine: `--server ws://localhost:8000`
→ If you have Anaconda: make sure venv is activated (`where.exe python` must show venv path)

**Windows — Activation script blocked**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**"Connection refused"**
→ Server not running
→ Wrong IP in --server flag
→ Firewall blocking port 8000

**"No session" error on /msg or /send**
→ Run `/session <user>` first
→ Both users must be online at same time for /session

**File not received**
→ Check `/search <peer>` shows 🟢 ONLINE
→ Session must be active — run `/session` first

**Port already in use**
→ Change `PORT=8001` in `.env`

**Can't reach server from another machine**
→ Check firewall allows port 8000 (see Server Setup Step 6)
→ Use server's LAN IP not localhost
→ Both machines must be on same network (or server must be port-forwarded for internet)