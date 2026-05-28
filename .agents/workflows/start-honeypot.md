---
description: Build and start the Ghost in the machine honeypot using Docker Compose
---
# Start the Honeypot Environment

This workflow safely stops any previous instances and starts the entire honeypot stack (Web Terminal, SSH Server, MongoDB, Ollama Brain) in detached mode.

1. Ensure no existing instances are running, which could cause port conflicts.
// turbo
```bash
docker-compose down
```

2. Build and start all services in detached mode
```bash
docker-compose up -d --build
```

3. Optionally, view the logs for the gateway service to confirm successful startup
```bash
docker-compose logs -f phantasm-gateway
```

## Local Development (Without Docker)

1. For the Web Terminal:
```bash
npm install
npm start
```
The Web Dashboard will run at http://localhost:3000

2. For the SSH Honeypot:
```bash
cd ssh_honeypot
pip install -r requirements.txt
cp .env.example .env
python ssh_server.py
```
The SSH Server will run at port 2222.
