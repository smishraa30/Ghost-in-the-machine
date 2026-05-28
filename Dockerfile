FROM python:3.10-slim

# Install system dependencies, Node.js 18, and build tools
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Node dependencies first (caching layer)
COPY package*.json ./
RUN npm install --production

# Install Python dependencies (caching layer)
COPY ssh_honeypot/requirements.txt ./ssh_honeypot/
RUN pip install --no-cache-dir -r ./ssh_honeypot/requirements.txt pyfiglet

# Copy the rest of the application code
COPY . .

# Expose Web (3000) and SSH (2222)
EXPOSE 3000 2222

# Create a unified startup script
RUN echo '#!/bin/bash\n\n# Start Python SSH server in the background\ncd /app/ssh_honeypot && python ssh_server.py &\n\n# Start Node.js Web Dashboard & Terminal\ncd /app && node server.js\n' > /app/start.sh \
    && chmod +x /app/start.sh

# Security Hardening: Run as non-root user
RUN useradd -m phantasm \
    && chown -R phantasm:phantasm /app \
    && mkdir -p /app/ssh_honeypot/logs \
    && chown -R phantasm:phantasm /app/ssh_honeypot/logs

USER phantasm

# Healthcheck to reset the container if compromised or crashed
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:3000/api/stats || exit 1

# Start the gateway
CMD ["/app/start.sh"]
