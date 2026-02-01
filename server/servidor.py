import asyncio
import json
import sqlite3
import threading
import datetime
import logging
import os
from flask import Flask, render_template, jsonify, request
import websockets

# Set working directory to script location
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Configuration
HOST = "0.0.0.0"
WS_PORT = 5600
WEB_PORT = 8080
DB_PATH = "sysremote.db"
HOST_TIMEOUT = 45  # 3x heartbeat of 15s

# Setup Logging
if not os.path.exists("logs"):
    os.makedirs("logs")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SysRemoteServer")

# ============================================================
# FIX 2: Suprimir erros de handshake causados por probes TCP
# A GUI do host faz TcpStream::connect na porta 5600 para
# diagnostico, envia 0 bytes e fecha. O filtro e aplicado nos
# handlers do root logger para pegar mensagens de todos os
# sub-loggers do websockets (websockets.server, etc).
# ============================================================
class HandshakeFilter(logging.Filter):
    def filter(self, record):
        msg = record.getMessage().lower()
        if "opening handshake failed" in msg or "did not receive a valid http request" in msg:
            return False
        return True

_hf = HandshakeFilter()
for _handler in logging.root.handlers:
    _handler.addFilter(_hf)
# ============================================================

# Database Setup
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS hosts
                 (host_id TEXT PRIMARY KEY, hostname TEXT, ip TEXT, user TEXT, os TEXT, last_seen DATETIME, status TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, viewer_id TEXT, host_id TEXT, start_time DATETIME, end_time DATETIME, duration INTEGER)''')
    conn.commit()
    conn.close()

# Flask App
app = Flask(__name__, template_folder='templates')

@app.route('/')
def index():
    return "SysRemote Server Running. Go to <a href='/admin'>/admin</a>"

@app.route('/admin')
def admin():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    hosts = conn.execute("SELECT * FROM hosts").fetchall()
    conn.close()
    return render_template('admin.html', hosts=hosts)

@app.route('/logs')
def logs():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    sessions = conn.execute("SELECT * FROM sessions ORDER BY start_time DESC").fetchall()
    conn.close()
    return render_template('logs.html', sessions=sessions)

@app.route('/api/hosts')
def api_hosts():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    hosts = conn.execute("SELECT * FROM hosts WHERE status='online'").fetchall()
    conn.close()
    return jsonify([dict(h) for h in hosts])

def run_flask():
    logger.info(f"Starting Web Server on {HOST}:{WEB_PORT}")
    app.run(host=HOST, port=WEB_PORT, debug=False, use_reloader=False)

# WebSocket Handler
connected_hosts = {}

async def update_host_status(host_id, status, hostname=None, ip=None, user=None, os_info=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        c.execute("SELECT 1 FROM hosts WHERE host_id = ?", (host_id,))
        exists = c.fetchone()
        
        if status == 'online':
            if exists:
                c.execute("UPDATE hosts SET last_seen = ?, status = ?, ip = ? WHERE host_id = ?", (now, status, ip, host_id))
                if hostname: 
                    c.execute("UPDATE hosts SET hostname = ?, user = ?, os = ? WHERE host_id = ?", (hostname, user, os_info, host_id))
            else:
                c.execute("INSERT INTO hosts (host_id, hostname, ip, user, os, last_seen, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                          (host_id, hostname, ip, user, os_info, now, status))
        else:
            if exists:
                c.execute("UPDATE hosts SET status = ? WHERE host_id = ?", (status, host_id))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"DB Error update_host_status: {e}")

async def log_session(viewer_id, host_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO sessions (viewer_id, host_id, start_time) VALUES (?, ?, ?)", (viewer_id, host_id, now))
        conn.commit()
        conn.close()
        logger.info(f"Session started: {viewer_id} -> {host_id}")
    except Exception as e:
        logger.error(f"DB Error log_session: {e}")

async def handle_message(websocket, message):
    try:
        data = json.loads(message)
        msg_type = data.get("type")
        
        if msg_type == "register_host":
            host_id = data.get("host_id")
            connected_hosts[host_id] = websocket
            await update_host_status(
                host_id, 'online', 
                data.get("hostname"), 
                data.get("ip"), 
                data.get("user"), 
                data.get("os")
            )
            logger.info(f"Host registered: {host_id}")
            
        elif msg_type == "list_hosts":
            # FIX 3: Incluir campo 'ip' na resposta
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT host_id, hostname, status, ip FROM hosts WHERE status='online'").fetchall()
            conn.close()
            
            hosts_list = [{"host_id": r["host_id"], "hostname": r["hostname"], "status": r["status"], "ip": r["ip"]} for r in rows]
            response = {"type": "host_list", "hosts": hosts_list}
            await websocket.send(json.dumps(response))
            
        elif msg_type == "connect_request":
            viewer_id = data.get("viewer_id")
            host_id = data.get("host_id")
            viewer_ip = data.get("viewer_ip")
            viewer_port = data.get("viewer_port")
            
            conn = sqlite3.connect(DB_PATH)
            row = conn.execute("SELECT ip, status FROM hosts WHERE host_id = ?", (host_id,)).fetchone()
            conn.close()
            
            if row and row[0]:
                host_ip = row[0]
                
                # --- CRITICAL: REVERSE CONNECT LOGIC ---
                # Se o Viewer mandou IP/Porta, tenta avisar o Host para conectar de volta
                if viewer_ip and viewer_port and host_id in connected_hosts:
                    try:
                        reverse_msg = {
                            "type": "reverse_connect",
                            "viewer_ip": viewer_ip,
                            "viewer_port": viewer_port,
                            "viewer_id": viewer_id
                        }
                        await connected_hosts[host_id].send(json.dumps(reverse_msg))
                        logger.info(f"Sent Reverse Connect to {host_id} for viewer {viewer_ip}:{viewer_port}")
                    except Exception as e:
                        logger.error(f"Failed to send Reverse Connect to {host_id}: {e}")
                # ---------------------------------------

                response = {
                    "type": "connect_response", 
                    "success": True, 
                    "host_ip": host_ip, 
                    "host_port": 5599
                }
                await log_session(viewer_id, host_id)
            else:
                response = {"type": "connect_response", "success": False, "error": "Host offline or not found"}
                
            await websocket.send(json.dumps(response))
            
        # FIX 4: Heartbeat implementado corretamente
        elif msg_type == "heartbeat":
            host_id = data.get("host_id")
            if host_id:
                try:
                    conn = sqlite3.connect(DB_PATH)
                    c = conn.cursor()
                    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    c.execute("UPDATE hosts SET last_seen = ?, status = 'online' WHERE host_id = ?", (now, host_id))
                    conn.commit()
                    conn.close()
                except Exception as e:
                    logger.error(f"Heartbeat DB error: {e}")

    except Exception as e:
        logger.error(f"Error handling message: {e}")

async def ws_handler(websocket):
    current_host_id = None
    try:
        logger.info("connection open")
        async for message in websocket:
            if current_host_id:
                 try:
                     conn = sqlite3.connect(DB_PATH)
                     c = conn.cursor()
                     now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                     c.execute("UPDATE hosts SET last_seen = ?, status = 'online' WHERE host_id = ?", (now, current_host_id))
                     conn.commit()
                     conn.close()
                 except Exception as e:
                     logger.error(f"DB error in ws_handler loop: {e}")

            data = json.loads(message)
            if data.get("type") == "register_host":
                current_host_id = data.get("host_id")
            
            await handle_message(websocket, message)
            
    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        # FIX 1: So marca offline se esta conexao ainda e a ativa
        if current_host_id:
            if connected_hosts.get(current_host_id) is websocket:
                logger.info(f"Host disconnected: {current_host_id}")
                del connected_hosts[current_host_id]
                await update_host_status(current_host_id, 'offline')
            else:
                logger.info(f"Connection closed for {current_host_id} (replaced by newer connection, not marking offline)")

async def host_cleaner():
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            threshold = datetime.datetime.now() - datetime.timedelta(seconds=HOST_TIMEOUT)
            threshold_str = threshold.strftime("%Y-%m-%d %H:%M:%S")
            
            c.execute("SELECT host_id FROM hosts WHERE status='online' AND last_seen < ?", (threshold_str,))
            offline_hosts = c.fetchall()
            
            if offline_hosts:
                c.execute("UPDATE hosts SET status='offline' WHERE status='online' AND last_seen < ?", (threshold_str,))
                conn.commit()
                for h in offline_hosts:
                    logger.info(f"Host marked offline (timeout): {h[0]}")
                    if h[0] in connected_hosts:
                        del connected_hosts[h[0]]
            
            conn.close()
        except Exception as e:
            logger.error(f"Cleaner error: {e}")
            
        await asyncio.sleep(10)

async def main():
    init_db()
    
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    logger.info(f"Starting WebSocket Server on {HOST}:{WS_PORT}")
    async with websockets.serve(ws_handler, HOST, WS_PORT):
        await host_cleaner()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopping...")