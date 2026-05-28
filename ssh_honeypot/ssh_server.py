import os
import sys
import socket
import threading
import asyncio
import logging
import uuid
import time
import traceback

import paramiko
from paramiko import RSAKey
from colorama import init, Fore, Style
from rich.console import Console
from rich.panel import Panel

import config
from ai_engine import AIEngine
from mongo_logger import MongoLogger
from sentiment_analyzer import SentimentAnalyzer
from visual_deception import VisualDeceptionEngine

init(autoreset=True)
console = Console()

os.makedirs(config.LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(config.LOG_DIR, "honeypot.log")),
        logging.StreamHandler() if config.CONSOLE_LOG else logging.NullHandler(),
    ],
)
logger = logging.getLogger("ghost.ssh")

def get_host_key():
    key_path = config.SSH_HOST_KEY_FILE
    if not os.path.exists(key_path):
        logger.info("Generating new RSA host key...")
        key = RSAKey.generate(2048)
        key.write_private_key_file(key_path)
        logger.info("Host key saved to %s", key_path)
        return key
    return RSAKey(filename=key_path)


class HoneypotServerInterface(paramiko.ServerInterface):
    """Paramiko server interface — accepts all auth attempts and logs credentials."""

    def __init__(self, mongo: MongoLogger, session_id: str, client_addr):
        super().__init__()
        self.mongo = mongo
        self.session_id = session_id
        self.client_addr = client_addr
        self.username = None
        self.password = None
        self.auth_attempts = 0
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.auth_attempts += 1
        self.username = username
        self.password = password

        self.mongo.log_credential(
            self.session_id, "ssh_login", username, password
        )
        logger.info(
            "%s[CRED CAPTURED]%s Session %s: %s:%s (attempt %d)",
            Fore.YELLOW, Style.RESET_ALL,
            self.session_id[:8], username, password, self.auth_attempts,
        )

        if self.auth_attempts >= 1:
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.username = username
        logger.info(
            "%s[PUBKEY]%s Session %s: user=%s key_type=%s",
            Fore.CYAN, Style.RESET_ALL,
            self.session_id[:8], username, key.get_name(),
        )
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height
                                   , pixelwidth, pixelheight, modes):
        return True

    def check_channel_env_request(self, channel, name, value):
        return True


class SessionHandler:
    """Handles a single attacker SSH session."""

    def __init__(self, channel, session_id, client_addr, mongo, ai, sentiment, visual):
        self.channel = channel
        self.session_id = session_id
        self.client_addr = client_addr
        self.mongo = mongo
        self.ai = ai
        self.sentiment = sentiment
        self.visual = visual
        self.command_count = 0
        self.cwd = config.DEFAULT_CWD
        self.loop = asyncio.new_event_loop()

    def handle(self):
        """Main session loop — reads commands and sends AI-generated responses."""
        try:
            banner = (
                f"Last login: {time.strftime('%a %b %d %H:%M:%S %Y')} from 10.0.3.1\r\n"
            )
            self.channel.sendall(banner.encode())
            self._send_prompt()

            self.ai.init_session(self.session_id)

            command_buffer = ""

            while True:
                try:
                    data = self.channel.recv(1024)
                    if not data:
                        break
                except socket.timeout:
                    continue

                for byte in data:
                    char = chr(byte)

                    if char == "\r" or char == "\n":
                        if command_buffer.strip():
                            self._process_command(command_buffer.strip())
                        command_buffer = ""
                        continue

                    if byte == 127 or byte == 8:
                        if command_buffer:
                            command_buffer = command_buffer[:-1]
                            self.channel.sendall(b"\b \b")
                        continue

                    if byte == 3:
                        self.channel.sendall(b"^C\r\n")
                        command_buffer = ""
                        self._send_prompt()
                        continue

                    if byte == 4:
                        self.channel.sendall(b"\r\nlogout\r\n")
                        return

                    if byte == 9:
                        continue

                    command_buffer += char
                    self.channel.sendall(bytes([byte]))

        except Exception as e:
            logger.error("Session %s error: %s", self.session_id[:8], e)
            traceback.print_exc()
        finally:
            self.ai.end_session(self.session_id)
            self.mongo.end_session(self.session_id)
            self.loop.close()
            logger.info(
                "%s[SESSION END]%s %s — %d commands processed",
                Fore.RED, Style.RESET_ALL,
                self.session_id[:8], self.command_count,
            )

    def _process_command(self, command):
        self.command_count += 1
        self.channel.sendall(b"\r\n")

        logger.info(
            "%s[CMD]%s Session %s (#%d): %s",
            Fore.GREEN, Style.RESET_ALL,
            self.session_id[:8], self.command_count, command,
        )

        if self._is_image_exfil(command):
            self._handle_image_exfil(command)
            return

        if command.strip() in ("exit", "logout", "quit"):
            self.channel.sendall(b"logout\r\nConnection to prod-srv-01 closed.\r\n")
            self.channel.close()
            return

        try:
            response = self.loop.run_until_complete(
                self.ai.process_command(self.session_id, command, mongo=self.mongo)
            )
        except Exception as e:
            logger.error("AI error: %s", e)
            response = f"bash: {command.split()[0] if command.split() else command}: command not found"

        time.sleep(0.1 + len(response) * 0.001)

        formatted = response.replace("\n", "\r\n")
        self.channel.sendall(formatted.encode("utf-8", errors="replace"))
        if not formatted.endswith("\r\n"):
            self.channel.sendall(b"\r\n")

        risk = self._assess_risk(command)
        self.mongo.log_command(
            self.session_id, command, response,
            risk_level=risk, command_type=self._classify_command(command),
        )

        if self.command_count % config.ANALYSIS_INTERVAL == 0:
            threading.Thread(
                target=self._run_analysis, daemon=True
            ).start()

        self._send_prompt()

    def _send_prompt(self):
        """Send the bash prompt."""
        cwd_display = self.cwd.replace("/home/admin", "~")
        prompt = f"{config.DEFAULT_USER}@{config.HOSTNAME}:{cwd_display}$ "
        self.channel.sendall(prompt.encode())

    def _is_image_exfil(self, command):
        """Check if the command is trying to exfiltrate image/document files."""
        exfil_patterns = ["scp", "base64", "xxd", "cat.*png", "cat.*jpg", "cat.*pdf",
                          "tar.*secret", "tar.*credential", "cat.*drawio"]
        cmd_lower = command.lower()
        return any(p in cmd_lower for p in exfil_patterns) and \
               any(ext in cmd_lower for ext in [".png", ".jpg", ".pdf", ".drawio", "secret", "credential"])

    def _handle_image_exfil(self, command):
        """Intercept image exfiltration and serve a fake document."""
        try:
            fake_path = self.visual.generate_fake_image_for_path(command)
            with open(fake_path, "rb") as f:
                fake_data = f.read()

            if "base64" in command.lower():
                import base64
                encoded = base64.b64encode(fake_data).decode()
                for i in range(0, len(encoded), 76):
                    self.channel.sendall((encoded[i:i + 76] + "\r\n").encode())
                    time.sleep(0.01)
            else:
                self.channel.sendall(
                    f"(binary data — {len(fake_data)} bytes)\r\n".encode()
                )

            self.mongo.log_command(
                self.session_id, command,
                f"[VISUAL DECEPTION] Served fake document ({len(fake_data)} bytes)",
                risk_level="critical",
                command_type="exfiltration_attempt",
            )
            logger.warning(
                "%s[EXFIL TRAP]%s Session %s: Served fake document for: %s",
                Fore.MAGENTA, Style.RESET_ALL,
                self.session_id[:8], command,
            )
        except Exception as e:
            logger.error("Visual deception error: %s", e)
            self.channel.sendall(b"cat: Permission denied\r\n")

        self._send_prompt()

    def _assess_risk(self, command):
        """Quick risk assessment of a command."""
        cmd_lower = command.lower()
        if any(k in cmd_lower for k in ["exploit", "cve", "reverse", "meterpreter", "payload"]):
            return "critical"
        if any(k in cmd_lower for k in ["sudo", "chmod +s", "shadow", "passwd", "docker run"]):
            return "high"
        if any(k in cmd_lower for k in ["nmap", "wget", "curl", "scp", "ssh", "nc "]):
            return "medium"
        return "low"

    def _classify_command(self, command):
        """Classify the command type."""
        cmd = command.strip().split()[0] if command.strip() else ""
        categories = {
            "recon": ["ls", "cat", "find", "grep", "ps", "netstat", "id", "whoami", "uname", "ifconfig"],
            "exploit": ["gcc", "chmod", "exploit", "sudo", "pkexec"],
            "network": ["nmap", "ping", "ssh", "scp", "curl", "wget", "nc"],
            "persistence": ["crontab", "echo", "ssh-keygen"],
            "exfiltration": ["tar", "zip", "base64", "scp"],
        }
        for cat, cmds in categories.items():
            if cmd in cmds:
                return cat
        return "general"

    def _run_analysis(self):
        try:
            analysis = self.sentiment.analyze_session(self.session_id)
            if analysis:
                logger.info(
                    "%s[ANALYSIS]%s Session %s: %s",
                    Fore.CYAN, Style.RESET_ALL,
                    self.session_id[:8], analysis.get("summary", ""),
                )
        except Exception as e:
            logger.error("Analysis error: %s", e)


class GhostSSHServer:
    """Main SSH honeypot server using Paramiko."""

    def __init__(self):
        self.host_key = get_host_key()
        self.mongo = MongoLogger()
        self.ai = AIEngine()
        self.sentiment = SentimentAnalyzer(self.mongo)
        self.visual = VisualDeceptionEngine()
        self.active_sessions = {}

    def start(self):
        """Start the SSH honeypot server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((config.SSH_HOST, config.SSH_PORT))
            sock.listen(100)
            sock.settimeout(None)
        except Exception as e:
            logger.critical("Failed to bind to %s:%d — %s", config.SSH_HOST, config.SSH_PORT, e)
            sys.exit(1)

        console.print(Panel.fit(
            f"[bold green]👻 GHOST IN THE MACHINE — SSH Honeypot Active[/bold green]\n\n"
            f"[cyan]Listening:[/cyan]    {config.SSH_HOST}:{config.SSH_PORT}\n"
            f"[cyan]Hostname:[/cyan]    {config.HOSTNAME}\n"
            f"[cyan]AI Provider:[/cyan] {config.AI_PROVIDER} ({config.OPENAI_MODEL if config.AI_PROVIDER == 'openai' else config.OLLAMA_MODEL})\n"
            f"[cyan]MongoDB:[/cyan]     {'Connected' if self.mongo.connected else 'In-Memory Fallback'}\n"
            f"[cyan]Banner:[/cyan]      {config.SSH_BANNER}\n\n"
            f"[dim]Waiting for connections...[/dim]",
            title="[bold red]HONEYPOT[/bold red]",
            border_style="red",
        ))

        while True:
            try:
                client, addr = sock.accept()
                logger.info(
                    "%s[NEW CONNECTION]%s %s:%d",
                    Fore.GREEN, Style.RESET_ALL, addr[0], addr[1],
                )
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client, addr),
                    daemon=True,
                )
                t.start()
            except KeyboardInterrupt:
                logger.info("Shutting down honeypot...")
                self.mongo.close()
                break
            except Exception as e:
                logger.error("Accept error: %s", e)

    def _handle_client(self, client_socket, addr):
        """Handle a new SSH client connection."""
        session_id = str(uuid.uuid4())

        try:
            transport = paramiko.Transport(client_socket)
            transport.local_version = config.SSH_BANNER
            transport.add_server_key(self.host_key)

            server = HoneypotServerInterface(
                self.mongo, session_id, addr
            )

            try:
                transport.start_server(server=server)
            except paramiko.SSHException as e:
                logger.warning("SSH negotiation failed from %s: %s", addr, e)
                return

            channel = transport.accept(60)
            if channel is None:
                logger.warning("No channel from %s", addr)
                return

            self.mongo.create_session(
                session_id,
                attacker_ip=addr[0],
                attacker_port=addr[1],
                username_tried=server.username or "unknown",
                password_tried=server.password or "unknown",
            )

            logger.info(
                "%s[SESSION START]%s %s from %s:%d (user: %s)",
                Fore.GREEN + Style.BRIGHT, Style.RESET_ALL,
                session_id[:8], addr[0], addr[1], server.username,
            )

            server.event.wait(10)

            handler = SessionHandler(
                channel, session_id, addr,
                self.mongo, self.ai, self.sentiment, self.visual,
            )
            self.active_sessions[session_id] = handler
            handler.handle()

        except Exception as e:
            logger.error("Client handler error (%s): %s", addr, e)
            traceback.print_exc()
        finally:
            self.active_sessions.pop(session_id, None)
            try:
                client_socket.close()
            except Exception:
                pass


if __name__ == "__main__":
    server = GhostSSHServer()
    server.start()
