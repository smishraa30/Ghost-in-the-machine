const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const os = require('os');
const config = require('./config');
const CommandProcessor = require('./modules/commandProcessor');
const SessionLogger = require('./modules/sessionLogger');
const WallMessageSystem = require('./modules/wallMessage');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

const logger = new SessionLogger();

const activeProcessors = new Map();

const terminalNs = io.of('/terminal');
terminalNs.on('connection', (socket) => {
  const sessionId = uuidv4();
  const ip = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || 'unknown';
  const userAgent = socket.handshake.headers['user-agent'] || 'unknown';

  const session = logger.createSession(sessionId, { ip, userAgent });
  const processor = new CommandProcessor(logger, sessionId);
  activeProcessors.set(sessionId, processor);

  const wall = new WallMessageSystem();
  wall.start((msg) => { socket.emit('output', msg); });

  console.log(`[+] New attacker session: ${sessionId} from ${ip}`);

  const banner = `Last login: ${new Date(Date.now() - 3600000).toUTCString()} from 10.0.3.1\n`;
  socket.emit('output', banner);
  socket.emit('prompt', processor.getPrompt());
  socket.emit('session-id', sessionId);

  let awaitingSudo = false;
  let sudoCommand = '';

  socket.on('command', async (cmdLine) => {
    if (awaitingSudo) {
      const result = processor.handleSudoPassword(cmdLine, sudoCommand);
      if (result.awaitingPassword) {
        socket.emit('output', result.output);
        socket.emit('password-prompt', true);
      } else {
        awaitingSudo = false;
        socket.emit('output', result.output + '\n');
        socket.emit('prompt', processor.getPrompt());
      }
      return;
    }

    const result = await processor.process(cmdLine);

    const delay = result.delay || 100;
    setTimeout(() => {
      if (result.output) {
        socket.emit('output', result.output + '\n');
      }

      if (result.awaitingPassword) {
        awaitingSudo = true;
        sudoCommand = result.sudoCommand || '';
        socket.emit('password-prompt', true);
        return;
      }

      if (result.shouldDisconnect) {
        wall.stop();
        logger.endSession(sessionId);
        activeProcessors.delete(sessionId);
        socket.emit('disconnected', true);
        return;
      }

      if (result.wallTrigger) {
        setTimeout(() => {
          wall.triggerReactive(result.wallTrigger);
        }, 5000 + Math.random() * 10000);
      }

      socket.emit('prompt', processor.getPrompt());
    }, delay);
  });

  socket.on('disconnect', () => {
    wall.stop();
    logger.endSession(sessionId);
    activeProcessors.delete(sessionId);
    console.log(`[-] Session ended: ${sessionId}`);
  });
});

const dashNs = io.of('/dashboard');
dashNs.on('connection', (socket) => {
  console.log('[Dashboard] Admin connected');

  socket.emit('stats', logger.getSessionStats());
  socket.emit('sessions', logger.getAllSessions().map(s => ({
    ...s,
    commands: s.commands.slice(-50),
  })));

  const interval = setInterval(() => {
    socket.emit('stats', logger.getSessionStats());
    socket.emit('sessions', logger.getAllSessions().map(s => ({
      ...s,
      commands: s.commands.slice(-50),
    })));
    socket.emit('active-count', logger.getActiveSessions().length);
  }, config.dashboard.refreshInterval);

  socket.on('disconnect', () => {
    clearInterval(interval);
    console.log('[Dashboard] Admin disconnected');
  });
});

app.get('/api/stats', (req, res) => {
  res.json(logger.getSessionStats());
});

app.get('/api/sessions', (req, res) => {
  res.json(logger.getAllSessions().map(s => ({
    id: s.id,
    ip: s.ip,
    startTime: s.startTime,
    endTime: s.endTime,
    active: s.active,
    totalCommands: s.totalCommands,
    riskScore: s.riskScore,
    exploitAttempts: s.exploitAttempts.length,
    credentialsCaptured: s.credentialsCaptured.length,
    tags: s.tags,
  })));
});

app.get('/api/sessions/:id', (req, res) => {
  const session = logger.getSession(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  res.json(session);
});

app.get('/api/sessions/:id/commands', (req, res) => {
  const session = logger.getSession(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  res.json(session.commands);
});

app.get('/api/sessions/:id/exploits', (req, res) => {
  const session = logger.getSession(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  res.json(session.exploitAttempts);
});

app.get('/api/sessions/:id/credentials', (req, res) => {
  const session = logger.getSession(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  res.json(session.credentialsCaptured);
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/about', (req, res) => res.sendFile(path.join(__dirname, 'public', 'landing.html')));
app.get('/landing', (req, res) => res.sendFile(path.join(__dirname, 'public', 'landing.html')));


server.listen(config.server.port, config.server.host, () => {
  const nets = os.networkInterfaces();
  let localIP = 'localhost';
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        localIP = net.address;
        break;
      }
    }
  }

  console.log(`Server listening on http://${localIP}:${config.server.port}`);
});
