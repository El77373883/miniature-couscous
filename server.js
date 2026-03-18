const express = require('express');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Rcon } = require('rcon-client');
const fetch = require('node-fetch');
const ftp = require('basic-ftp');
const multer = require('multer');
const path = require('path');
const { Readable, Writable } = require('stream');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET || 'adrianpanel2024';
const ADMIN_USER = 'admin2005';
const ADMIN_PASS = '2005admin';

['data','data/logs','data/plugins','public'].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

const readJSON = (f, d=[]) => { try { return JSON.parse(fs.readFileSync(f,'utf8')); } catch { return d; } };
const writeJSON = (f, data) => fs.writeFileSync(f, JSON.stringify(data, null, 2));

const initAdmin = () => {
  const users = readJSON('data/users.json');
  if (!users.find(u => u.username === ADMIN_USER)) {
    users.push({ id:'admin_1', username:ADMIN_USER, email:'admin@adrianpanel.com', passwordHash:bcrypt.hashSync(ADMIN_PASS,10), role:'admin', createdAt:new Date().toISOString() });
    writeJSON('data/users.json', users);
    console.log('✅ Admin creado: admin2005 / 2005admin');
  }
};
initAdmin();

const serverLogs = {};
const serverErrors = {};
const serverMetrics = {};

const addLog = (sid, tag, type, msg) => {
  if (!serverLogs[sid]) serverLogs[sid] = [];
  const entry = { id: Date.now()+Math.random(), time: new Date().toLocaleTimeString('es',{hour12:false}), tag, type, msg };
  serverLogs[sid].push(entry);
  if (serverLogs[sid].length > 300) serverLogs[sid].shift();
  detectErrors(sid, msg, tag);
};

const errorPatterns = ['Exception','Error','WARN','Stacktrace','OutOfMemory','Caused by','Failed to','Unable to','Cannot','NullPointer','ArrayIndexOutOfBounds','Connection refused','Timeout'];

const detectErrors = (sid, msg, tag) => {
  if (!serverErrors[sid]) serverErrors[sid] = [];
  const matched = errorPatterns.find(p => msg.includes(p));
  if (matched) {
    const severity = msg.includes('Exception')||msg.includes('OutOfMemory')||msg.includes('NullPointer') ? 'CRITICAL' : msg.includes('WARN') ? 'WARNING' : 'INFO';
    serverErrors[sid].push({ id:'e_'+Date.now(), timestamp: new Date().toISOString(), type: severity, category: matched, message: msg, resolved: false });
    if (serverErrors[sid].length > 500) serverErrors[sid].shift();
  }
};

const updateMetrics = (sid) => {
  if (!serverMetrics[sid]) serverMetrics[sid] = { cpu: Array(60).fill(0), ram: Array(60).fill(0), tps: Array(60).fill(20), net: Array(60).fill(0) };
  const m = serverMetrics[sid];
  const lastCpu = m.cpu[m.cpu.length-1] || 20;
  const lastRam = m.ram[m.ram.length-1] || 40;
  const lastTps = m.tps[m.tps.length-1] || 20;
  m.cpu = [...m.cpu.slice(1), Math.min(95, Math.max(5, lastCpu + (Math.random()-.48)*12))];
  m.ram = [...m.ram.slice(1), Math.min(90, Math.max(20, lastRam + (Math.random()-.48)*8))];
  m.tps = [...m.tps.slice(1), Math.min(20, Math.max(0, lastTps + (Math.random()-.48)*2))];
  m.net = [...m.net.slice(1), Math.round(Math.random()*100)];
};

setInterval(() => {
  const servers = readJSON('data/servers.json');
  servers.forEach(s => updateMetrics(s.id));
}, 3000);

const auth = (req,res,next) => {
  const token = req.headers['x-token'];
  if (!token) return res.status(401).json({error:'No autorizado'});
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({error:'Token inválido'}); }
};

const adminOnly = (req,res,next) => {
  if (req.user.role !== 'admin') return res.status(403).json({error:'Solo el admin puede hacer esto'});
  next();
};

app.post('/api/auth/register', async (req,res) => {
  const {username,email,password} = req.body;
  if (!username||!email||!password) return res.status(400).json({error:'Faltan campos'});
  const users = readJSON('data/users.json');
  if (users.find(u=>u.username===username)) return res.status(400).json({error:'Usuario ya existe'});
  if (users.find(u=>u.email===email)) return res.status(400).json({error:'Email ya registrado'});
  const user = { id:'u_'+Date.now(), username, email, passwordHash:await bcrypt.hash(password,10), role: username===ADMIN_USER?'admin':'user', createdAt:new Date().toISOString() };
  users.push(user);
  writeJSON('data/users.json', users);
  const token = jwt.sign({id:user.id,username:user.username,role:user.role}, JWT_SECRET, {expiresIn:'7d'});
  res.json({ok:true, token, user:{id:user.id,username:user.username,email:user.email,role:user.role}});
});

app.post('/api/auth/login', async (req,res) => {
  const {username,password} = req.body;
  const users = readJSON('data/users.json');
  const user = users.find(u=>u.username===username);
  if (!user||!await bcrypt.compare(password,user.passwordHash)) return res.status(401).json({error:'Usuario o contraseña incorrectos'});
  const token = jwt.sign({id:user.id,username:user.username,role:user.role}, JWT_SECRET, {expiresIn:'7d'});
  res.json({ok:true, token, user:{id:user.id,username:user.username,email:user.email,role:user.role}});
});

app.post('/api/auth/change-password', auth, async (req,res) => {
  const {oldPassword,newPassword} = req.body;
  const users = readJSON('data/users.json');
  const idx = users.findIndex(u=>u.id===req.user.id);
  if (!await bcrypt.compare(oldPassword,users[idx].passwordHash)) return res.status(400).json({error:'Contraseña actual incorrecta'});
  users[idx].passwordHash = await bcrypt.hash(newPassword,10);
  writeJSON('data/users.json', users);
  res.json({ok:true});
});

app.get('/api/servers', auth, (req,res) => {
  const servers = readJSON('data/servers.json');
  res.json(servers.filter(s=>s.userId===req.user.id));
});

app.post('/api/servers', auth, (req,res) => {
  const servers = readJSON('data/servers.json');
  const server = {id:'s_'+Date.now(), userId:req.user.id, ...req.body, createdAt:new Date().toISOString()};
  servers.push(server);
  writeJSON('data/servers.json', servers);
  res.json(server);
});

app.put('/api/servers/:id', auth, (req,res) => {
  const servers = readJSON('data/servers.json');
  const idx = servers.findIndex(s=>s.id===req.params.id&&s.userId===req.user.id);
  if (idx===-1) return res.status(404).json({error:'No encontrado'});
  servers[idx] = {...servers[idx],...req.body};
  writeJSON('data/servers.json', servers);
  res.json(servers[idx]);
});

app.delete('/api/servers/:id', auth, (req,res) => {
  let servers = readJSON('data/servers.json');
  servers = servers.filter(s=>!(s.id===req.params.id&&s.userId===req.user.id));
  writeJSON('data/servers.json', servers);
  res.json({ok:true});
});

app.get('/api/servers/:id/status', auth, async (req,res) => {
  const servers = readJSON('data/servers.json');
  const server = servers.find(s=>s.id===req.params.id&&s.userId===req.user.id);
  if (!server) return res.status(404).json({error:'No encontrado'});
  try {
    const r = await fetch(`https://api.mcsrvstat.us/3/${server.ip}`);
    res.json(await r.json());
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/servers/:id/rcon', auth, async (req,res) => {
  const servers = readJSON('data/servers.json');
  const server = servers.find(s=>s.id===req.params.id&&s.userId===req.user.id);
  if (!server) return res.status(404).json({error:'No encontrado'});
  const {command} = req.body;
  addLog(server.id,'CMD','cmd','/'+command);
  if (!server.rconPass) { const m='⚠ RCON no configurado.'; addLog(server.id,'WARN','warn',m); return res.json({response:m}); }
  try {
    const rcon = new Rcon({host:server.rconHost||server.ip, port:parseInt(server.rconPort)||25575, password:server.rconPass, timeout:5000});
    await rcon.connect();
    const response = await rcon.send(command);
    await rcon.end();
    const reply = response||'Comando ejecutado.';
    addLog(server.id,'INFO','success',reply);
    res.json({response:reply});
  } catch(e) {
    const err='Error RCON: '+e.message;
    addLog(server.id,'ERROR','error',err);
    res.status(500).json({error:err});
  }
});

app.get('/api/servers/:id/logs', auth, (req,res) => {
  const since = parseFloat(req.query.since)||0;
  const logs = serverLogs[req.params.id]||[];
  res.json(since ? logs.filter(l=>l.id>since) : logs);
});

app.get('/api/servers/:id/metrics', auth, (req,res) => {
  const m = serverMetrics[req.params.id] || { cpu:Array(60).fill(0), ram:Array(60).fill(0), tps:Array(60).fill(20), net:Array(60).fill(0) };
  res.json({ cpu: Math.round(m.cpu[m.cpu.length-1]), ram: Math.round(m.ram[m.ram.length-1]), tps: Math.round(m.tps[m.tps.length-1]*10)/10, net: m.net[m.net.length-1], history: m });
});

app.get('/api/servers/:id/errors', auth, (req,res) => {
  res.json(serverErrors[req.params.id]||[]);
});

app.post('/api/servers/:id/errors/:eid/resolve', auth, (req,res) => {
  const errors = serverErrors[req.params.id]||[];
  const e = errors.find(e=>e.id===req.params.eid);
  if (e) e.resolved = true;
  res.json({ok:true});
});

delete app.delete;
app.delete('/api/servers/:id/errors', auth, (req,res) => {
  serverErrors[req.params.id] = [];
  res.json({ok:true});
});

const getServer = (req,res) => {
  const servers = readJSON('data/servers.json');
  const s = servers.find(s=>s.id===req.params.id&&s.userId===req.user.id);
  if (!s) { res.status(404).json({error:'No encontrado'}); return null; }
  return s;
};

const ftpConn = async (server) => {
  const client = new ftp.Client(10000);
  await client.access({host:server.ftpHost||server.ip, port:parseInt(server.ftpPort)||21, user:server.ftpUser, password:server.ftpPass, secure:false});
  return client;
};

app.get('/api/servers/:id/ftp/list', auth, async (req,res) => {
  const server = getServer(req,res); if (!server) return;
  let client;
  try {
    client = await ftpConn(server);
    const list = await client.list(req.query.path||'/');
    res.json(list.map(f=>({name:f.name,size:f.size,date:f.rawModifiedAt,isDir:f.isDirectory})));
  } catch(e) { res.status(500).json({error:e.message}); }
  finally { if(client) client.close(); }
});

app.get('/api/servers/:id/ftp/read', auth, async (req,res) => {
  const server = getServer(req,res); if (!server) return;
  let client;
  try {
    client = await ftpConn(server);
    const chunks = [];
    const w = new Writable({ write(chunk,enc,cb) { chunks.push(chunk); cb(); } });
    await client.downloadTo(w, req.query.path);
    res.json({content: Buffer.concat(chunks).toString('utf8')});
  } catch(e) { res.status(500).json({error:e.message}); }
  finally { if(client) client.close(); }
});

app.post('/api/servers/:id/ftp/write', auth, async (req,res) => {
  const server = getServer(req,res); if (!server) return;
  let client;
  try {
    client = await ftpConn(server);
    const s = Readable.from([Buffer.from(req.body.content,'utf8')]);
    await client.uploadFrom(s, req.body.path);
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
  finally { if(client) client.close(); }
});

app.delete('/api/servers/:id/ftp/delete', auth, async (req,res) => {
  const server = getServer(req,res); if (!server) return;
  let client;
  try {
    client = await ftpConn(server);
    await client.remove(req.query.path);
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
  finally { if(client) client.close(); }
});

app.post('/api/servers/:id/ftp/mkdir', auth, async (req,res) => {
  const server = getServer(req,res); if (!server) return;
  let client;
  try {
    client = await ftpConn(server);
    await client.ensureDir(req.body.path);
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
  finally { if(client) client.close(); }
});

const uploadFTP = multer({storage: multer.memoryStorage()});
app.post('/api/servers/:id/ftp/upload', auth, uploadFTP.single('file'), async (req,res) => {
  const server = getServer(req,res); if (!server) return;
  let client;
  try {
    client = await ftpConn(server);
    const s = Readable.from([req.file.buffer]);
    await client.uploadFrom(s, (req.body.path||'/') + '/' + req.file.originalname);
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
  finally { if(client) client.close(); }
});

const pluginStorage = multer.diskStorage({
  destination: (req,file,cb) => cb(null,'data/plugins'),
  filename: (req,file,cb) => cb(null, file.originalname)
});
const uploadPlugin = multer({storage: pluginStorage});

app.get('/api/plugins', auth, (req,res) => res.json(readJSON('data/plugins-list.json')));

app.post('/api/plugins/upload', auth, adminOnly, uploadPlugin.single('file'), (req,res) => {
  if (!req.file) return res.status(400).json({error:'No se subió archivo'});
  const plugins = readJSON('data/plugins-list.json');
  const plugin = { id:'p_'+Date.now(), filename:req.file.originalname, name:req.body.name||req.file.originalname.replace('.jar',''), description:req.body.description||'Plugin', category:req.body.category||'General', uploadedAt:new Date().toISOString(), uploadedBy:req.user.username };
  plugins.push(plugin);
  writeJSON('data/plugins-list.json', plugins);
  res.json({ok:true, plugin});
});

app.delete('/api/plugins/:id', auth, adminOnly, (req,res) => {
  const plugins = readJSON('data/plugins-list.json');
  const plugin = plugins.find(p=>p.id===req.params.id);
  if (!plugin) return res.status(404).json({error:'No encontrado'});
  const fp = path.join('data/plugins', plugin.filename);
  if (fs.existsSync(fp)) fs.unlinkSync(fp);
  writeJSON('data/plugins-list.json', plugins.filter(p=>p.id!==req.params.id));
  res.json({ok:true});
});

app.get('/api/plugins/:id/download', auth, (req,res) => {
  const plugins = readJSON('data/plugins-list.json');
  const plugin = plugins.find(p=>p.id===req.params.id);
  if (!plugin) return res.status(404).json({error:'No encontrado'});
  const fp = path.join('data/plugins', plugin.filename);
  if (!fs.existsSync(fp)) return res.status(404).json({error:'Archivo no encontrado'});
  res.download(fp, plugin.filename);
});

app.get('/api/servers/:id/schedules', auth, (req,res) => {
  const all = readJSON('data/schedules.json');
  res.json(all.filter(s=>s.serverId===req.params.id&&s.userId===req.user.id));
});

app.post('/api/servers/:id/schedules', auth, (req,res) => {
  const all = readJSON('data/schedules.json');
  const sched = {id:'sch_'+Date.now(), serverId:req.params.id, userId:req.user.id, ...req.body, createdAt:new Date().toISOString()};
  all.push(sched);
  writeJSON('data/schedules.json', all);
  res.json(sched);
});

app.delete('/api/servers/:id/schedules/:sid', auth, (req,res) => {
  let all = readJSON('data/schedules.json');
  all = all.filter(s=>!(s.id===req.params.sid&&s.userId===req.user.id));
  writeJSON('data/schedules.json', all);
  res.json({ok:true});
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`✅ AdrianPanel corriendo en puerto ${PORT}`));
