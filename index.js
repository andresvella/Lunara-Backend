require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const OpenAI = require('openai');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'bdlunara',
  waitForConnections: true, connectionLimit: 10, queueLimit: 0,
  charset: 'utf8mb4'
});
const JWT_SECRET = process.env.JWT_SECRET;
const ai = process.env.OPENAI_API_KEY
  ? new OpenAI({
      apiKey: process.env.OPENAI_API_KEY,
      baseURL:
        process.env.OPENAI_API_URL ||
        'https://openrouter.ai/api/v1',
      defaultHeaders: {
        'HTTP-Referer': 'http://localhost:3000',
        'X-Title': 'Lunara AI',
      },
    })
  : null;

function auth(req, res, next) {
  const value = req.headers.authorization || '';
  const token = value.startsWith('Bearer ') ? value.slice(7) : '';
  if (!token || !JWT_SECRET) return res.status(401).json({ error: 'Inicia sesión para continuar.' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Sesión inválida o vencida. Inicia sesión otra vez.' }); }
}
function safeError(res, error, fallback='Error interno del servidor.') {
  console.error(error);
  return res.status(500).json({ error: fallback });
}
app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: 'connected', aiConfigured: Boolean(ai) });
  } catch (e) { res.status(503).json({ ok: false, database: 'disconnected', aiConfigured: Boolean(ai) }); }
});

app.post('/api/auth/register', async (req, res) => {
  const nombre = String(req.body.nombre || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (nombre.length < 2 || nombre.length > 100) return res.status(400).json({ error: 'El nombre debe tener entre 2 y 100 caracteres.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 150) return res.status(400).json({ error: 'Correo electrónico no válido.' });
  if (password.length < 8 || password.length > 72) return res.status(400).json({ error: 'La contraseña debe tener entre 8 y 72 caracteres.' });
  try {
    const [exists] = await pool.execute('SELECT id FROM usuarios WHERE email = ?', [email]);
    if (exists.length) return res.status(409).json({ error: 'Ya existe una cuenta con ese correo.' });
    const hash = await bcrypt.hash(password, 12);
    const id = crypto.randomUUID();
    await pool.execute("INSERT INTO usuarios (id, nombre, email, password_hash, estado) VALUES (?, ?, ?, ?, 'activo')", [id, nombre, email, hash]);
    const [plans] = await pool.execute("SELECT id FROM planes WHERE codigo='flash' LIMIT 1");
    if (plans.length) await pool.execute("INSERT INTO suscripciones (id, usuario_id, plan_id, estado) VALUES (?, ?, ?, 'activa')", [crypto.randomUUID(), id, plans[0].id]);
    const token = jwt.sign({ id, email, nombre }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id, nombre, email } });
  } catch (e) { safeError(res, e); }
});

app.post('/api/auth/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!email || !password) return res.status(400).json({ error: 'Escribe tu correo y contraseña.' });
  try {
    const [rows] = await pool.execute("SELECT id, nombre, email, password_hash, estado FROM usuarios WHERE email = ? LIMIT 1", [email]);
    const user = rows[0];
    if (!user || !user.password_hash || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
    if (user.estado !== 'activo') return res.status(403).json({ error: 'Esta cuenta no está activa.' });
    const token = jwt.sign({ id: user.id, email: user.email, nombre: user.nombre }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, nombre: user.nombre, email: user.email } });
  } catch (e) { safeError(res, e); }
});
app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));

app.get('/api/chats', auth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT c.id, c.titulo, c.creado_en, c.actualizado_en, m.codigo AS modelo
       FROM conversaciones c JOIN modelos_ia m ON m.id=c.modelo_id
       WHERE c.usuario_id=? ORDER BY c.actualizado_en DESC LIMIT 100`, [req.user.id]);
    res.json({ chats: rows });
  } catch (e) { safeError(res, e); }
});
app.post('/api/chats', auth, async (req, res) => {
  const titulo = String(req.body.titulo || 'Nueva conversación').trim().slice(0, 200) || 'Nueva conversación';
  const modelo = req.body.modelo === 'lunara-2.0-pro' ? 'lunara-2.0-pro' : 'lunara-2.0-flash';
  try {
    const [models] = await pool.execute('SELECT id FROM modelos_ia WHERE codigo=? AND activo=1 LIMIT 1', [modelo]);
    if (!models.length) return res.status(400).json({ error: 'El modelo seleccionado no está disponible.' });
    const id = crypto.randomUUID();
    await pool.execute('INSERT INTO conversaciones (id, usuario_id, modelo_id, titulo) VALUES (?, ?, ?, ?)', [id, req.user.id, models[0].id, titulo]);
    res.status(201).json({ chat: { id, titulo, modelo } });
  } catch (e) { safeError(res, e); }
});
app.get('/api/chats/:id/messages', auth, async (req, res) => {
  try {
    const [owns] = await pool.execute('SELECT id FROM conversaciones WHERE id=? AND usuario_id=?', [req.params.id, req.user.id]);
    if (!owns.length) return res.status(404).json({ error: 'Conversación no encontrada.' });
    const [messages] = await pool.execute("SELECT id, rol, contenido, creado_en FROM mensajes WHERE conversacion_id=? AND rol IN ('user','assistant') ORDER BY creado_en ASC", [req.params.id]);
    res.json({ messages });
  } catch (e) { safeError(res, e); }
});
app.delete('/api/chats/:id', auth, async (req, res) => {
  try {
    const [result] = await pool.execute('DELETE FROM conversaciones WHERE id=? AND usuario_id=?', [req.params.id, req.user.id]);
    if (!result.affectedRows) return res.status(404).json({ error: 'Conversación no encontrada.' });
    res.json({ ok: true });
  } catch (e) { safeError(res, e); }
});

app.post('/api/chat', auth, async (req, res) => {
  const message = String(req.body.message || '').trim();
  let chatId = String(req.body.chatId || '');
  const model = req.body.model === 'lunara-2.0-pro' ? 'lunara-2.0-pro' : 'lunara-2.0-flash';
  if (!message) return res.status(400).json({ error: 'Escribe un mensaje.' });
  if (message.length > 12000) return res.status(413).json({ error: 'El mensaje supera el límite de 12.000 caracteres.' });
  if (!ai) return res.status(503).json({ error: 'La IA no está configurada. Añade OPENAI_API_KEY al archivo .env y reinicia el servidor.' });
  try {
    let [owned] = chatId ? await pool.execute('SELECT c.id, c.titulo FROM conversaciones c WHERE c.id=? AND c.usuario_id=?', [chatId, req.user.id]) : [[]];
    if (!owned.length) {
      const [models] = await pool.execute('SELECT id FROM modelos_ia WHERE codigo=? LIMIT 1', [model]);
      if (!models.length) return res.status(500).json({ error: 'No se encontró el modelo en la base de datos.' });
      chatId = crypto.randomUUID();
      const title = message.slice(0, 70);
      await pool.execute('INSERT INTO conversaciones (id, usuario_id, modelo_id, titulo) VALUES (?, ?, ?, ?)', [chatId, req.user.id, models[0].id, title]);
    }
    await pool.execute("INSERT INTO mensajes (id, conversacion_id, rol, contenido) VALUES (?, ?, 'user', ?)", [crypto.randomUUID(), chatId, message]);
    const [history] = await pool.execute("SELECT rol, contenido FROM mensajes WHERE conversacion_id=? AND rol IN ('user','assistant') ORDER BY creado_en DESC LIMIT 20", [chatId]);
    const messages = history.reverse().map(m => ({ role: m.rol, content: m.contenido }));
    const completion = await ai.chat.completions.create({
      model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
      messages: [{ role: 'system', content: 'Eres Lunara AI, un asistente útil, claro y seguro. Responde en el idioma del usuario y reconoce cuando no sabes algo.' }, ...messages],
      max_tokens: 1800,
      temperature: 0.7
    });
    const answer = completion.choices?.[0]?.message?.content?.trim();
    if (!answer) throw new Error('El proveedor de IA devolvió una respuesta vacía.');
    await pool.execute("INSERT INTO mensajes (id, conversacion_id, rol, contenido, tokens_usados) VALUES (?, ?, 'assistant', ?, ?)", [crypto.randomUUID(), chatId, answer, completion.usage?.total_tokens || 0]);
    await pool.execute('UPDATE conversaciones SET actualizado_en=CURRENT_TIMESTAMP WHERE id=?', [chatId]);
    res.json({ answer, chatId, model, usage: completion.usage?.total_tokens || 0 });
  } catch (e) {
    if (e.status === 401 || e.status === 429 || e.status >= 500) {
      console.error('AI provider error:', e.message);
      return res.status(502).json({ error: e.status === 429 ? 'La IA alcanzó el límite de uso del proveedor. Inténtalo más tarde.' : 'No se pudo obtener respuesta de la IA. Verifica la clave y el modelo configurados.' });
    }
    return safeError(res, e);
  }
});

app.get('/api/planes', async (_req, res) => {
  try { const [rows] = await pool.query('SELECT nombre, codigo, precio_usd, periodo, busqueda_web, limite_mensajes_dia FROM planes ORDER BY precio_usd'); res.json({ planes: rows }); }
  catch (e) { safeError(res, e); }
});

const port = Number(process.env.PORT || 3000);
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.warn('ADVERTENCIA: configura JWT_SECRET con al menos 32 caracteres en .env antes de usar el servidor.');
}
app.listen(port, () => console.log(`Lunara AI listo en http://localhost:${port}`));
