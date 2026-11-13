// Perguntez — servidor (Cloudflare Pages "advanced mode" + D1, binding "DB").
// Este _worker.js funciona com deploy por Git, por "wrangler pages deploy" E pelo
// upload arrastando a pasta no painel (que ignora a pasta functions/).
// Rotas /api/* são a API; todo o resto é servido pelos arquivos estáticos.

const SESSION_DAYS = 30;
const MAX_FOTO_CHARS = 400000; // ~300 KB em base64
const encoder = new TextEncoder();

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders,
    },
  });
}

const toHex = (buf) => [...new Uint8Array(buf)].map((v) => v.toString(16).padStart(2, "0")).join("");

function randomHex(bytes = 32) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return toHex(data);
}

async function sha256(value) {
  return toHex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

// O Cloudflare Workers em produção limita PBKDF2 a 100.000 iterações
// (acima disso a chamada lança NotSupportedError e o cadastro/login retorna 500).
async function passwordHash(password, salt, iterations = 100000) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: encoder.encode(salt), iterations },
    key,
    256
  );
  return toHex(bits);
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  const item = raw.split(";").map((v) => v.trim()).find((v) => v.startsWith(name + "="));
  return item ? decodeURIComponent(item.slice(name.length + 1)) : "";
}

// Em produção: SameSite=Lax. Para testar dentro de um iframe (ex.: preview), defina
// COOKIE_SAMESITE=None nas variáveis locais (.dev.vars).
let cookieSameSite = "Lax";
function cookieHeader(value, maxAge) {
  const extra = cookieSameSite === "None" ? "SameSite=None; Partitioned" : "SameSite=Lax";
  return `pq_session=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; ${extra}; Max-Age=${maxAge}`;
}

function adminUsernames(env) {
  return String(env.ADMIN_USERNAMES || "felipe,fefe")
    .split(",").map((v) => v.trim().toLowerCase()).filter(Boolean);
}
const isAdminName = (env, username) => adminUsernames(env).includes(String(username || "").toLowerCase());

async function readJson(request) {
  try {
    const body = await request.json();
    return body && typeof body === "object" ? body : {};
  } catch {
    throw new HttpError(400, "Dados enviados em formato inválido.");
  }
}

async function currentUser(request, env) {
  const token = getCookie(request, "pq_session");
  if (!token) return null;
  const row = await env.DB.prepare(`
    SELECT u.id, u.username, u.email, u.sobre, u.created_at, u.is_admin,
           CASE WHEN u.foto IS NULL OR u.foto = '' THEN 0 ELSE length(u.foto) END AS foto_v
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ?
  `).bind(await sha256(token), new Date().toISOString()).first();
  return row || null;
}

async function requireUser(request, env, message) {
  const user = await currentUser(request, env);
  if (!user) throw new HttpError(401, message || "Faça login para continuar.");
  return user;
}

async function requireAdmin(request, env) {
  const user = await requireUser(request, env, "Faça login como administrador.");
  if (!user.is_admin) throw new HttpError(403, "Apenas administradores podem fazer isso.");
  return user;
}

/* ------------------------- Esquema do banco ------------------------- */
// "CREATE TABLE IF NOT EXISTS" NÃO altera uma tabela que já existe. Se a tabela
// users foi criada antes com outras colunas (ex.: sem password_salt/password_hash),
// o INSERT do cadastro falhava com "no such column" -> erro 500 genérico.
// Por isso o esquema é verificado e reparado automaticamente (uma vez por instância).

const TABLES = [
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    foto TEXT,
    sobre TEXT NOT NULL DEFAULT '',
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )`,
  `CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    titulo TEXT NOT NULL,
    categoria TEXT NOT NULL,
    autor TEXT NOT NULL,
    descricao TEXT NOT NULL DEFAULT '',
    anonima INTEGER NOT NULL DEFAULT 0 CHECK (anonima IN (0,1)),
    views INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    autor TEXT NOT NULL,
    texto TEXT NOT NULL,
    votes INTEGER NOT NULL DEFAULT 0,
    melhor INTEGER NOT NULL DEFAULT 0 CHECK (melhor IN (0,1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS follows (
    follower_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    following_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY(follower_id, following_id), CHECK(follower_id <> following_id)
  )`,
  `CREATE TABLE IF NOT EXISTS likes (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL CHECK(target_type IN ('question','answer')),
    target_id INTEGER NOT NULL,
    reaction TEXT NOT NULL CHECK(reaction IN ('like','dislike')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY(user_id,target_type,target_id)
  )`,
  `CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    answer_id INTEGER NOT NULL REFERENCES answers(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    text TEXT NOT NULL CHECK(length(text) BETWEEN 2 AND 1000),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )`,
  `CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    actor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    question_id INTEGER REFERENCES questions(id) ON DELETE CASCADE,
    answer_id INTEGER REFERENCES answers(id) ON DELETE CASCADE,
    text TEXT NOT NULL DEFAULT '',
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )`,
  `CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    text TEXT NOT NULL CHECK(length(text) BETWEEN 1 AND 1000),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )`,
];

// Colunas que o código usa. Se faltarem em uma tabela antiga, são adicionadas.
// (ALTER TABLE ADD COLUMN no SQLite exige DEFAULT constante para colunas NOT NULL.)
const REQUIRED_COLUMNS = {
  users: {
    // Bancos antigos podem ter username como PRIMARY KEY e não possuir users.id.
    // A coluna id é adicionada abaixo e recebe um índice UNIQUE para as FKs.
    id: "INTEGER", username: "TEXT", email: "TEXT",
    password_salt: "TEXT NOT NULL DEFAULT ''", password_hash: "TEXT NOT NULL DEFAULT ''",
    foto: "TEXT", sobre: "TEXT NOT NULL DEFAULT ''", is_admin: "INTEGER NOT NULL DEFAULT 0",
    created_at: "TEXT",
  },
  questions: {
    user_id: "INTEGER", titulo: "TEXT NOT NULL DEFAULT ''", categoria: "TEXT NOT NULL DEFAULT ''",
    autor: "TEXT NOT NULL DEFAULT ''", descricao: "TEXT NOT NULL DEFAULT ''",
    anonima: "INTEGER NOT NULL DEFAULT 0", views: "INTEGER NOT NULL DEFAULT 0", created_at: "TEXT",
  },
  answers: {
    question_id: "INTEGER", user_id: "INTEGER", autor: "TEXT NOT NULL DEFAULT ''",
    texto: "TEXT NOT NULL DEFAULT ''", votes: "INTEGER NOT NULL DEFAULT 0",
    melhor: "INTEGER NOT NULL DEFAULT 0", created_at: "TEXT",
  },
  messages: {
    is_read: "INTEGER NOT NULL DEFAULT 0",
  },
};

const SESSION_COLUMNS = ["id", "user_id", "token_hash", "expires_at", "created_at"];

const INDEXES = [
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase ON users(username COLLATE NOCASE)",
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_nocase ON users(email COLLATE NOCASE)",
  "CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash)",
  "CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at)",
  "CREATE INDEX IF NOT EXISTS idx_questions_created ON questions(id DESC)",
  "CREATE INDEX IF NOT EXISTS idx_answers_question ON answers(question_id, melhor DESC, votes DESC, id ASC)",
  "CREATE INDEX IF NOT EXISTS idx_follows_following ON follows(following_id)",
  "CREATE INDEX IF NOT EXISTS idx_likes_target ON likes(target_type,target_id)",
  "CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id,id DESC)",
  "CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id,receiver_id,id)",
];

// Colunas NOT NULL sem DEFAULT que existam numa tabela users antiga e que este código
// não conhece (ex.: "password", "nome"). Sem preenchê-las, o INSERT falharia.
let legacyUserColumns = [];
let schemaReady = null;

const quoteIdent = (name) => `"${String(name).replace(/"/g, '""')}"`;

async function tableColumns(env, table) {
  const { results } = await env.DB.prepare(`PRAGMA table_info(${quoteIdent(table)})`).all();
  return results || [];
}

async function migrateSchema(env) {
  await env.DB.batch(TABLES.map((sql) => env.DB.prepare(sql)));

  for (const [table, columns] of Object.entries(REQUIRED_COLUMNS)) {
    const existing = new Set((await tableColumns(env, table)).map((c) => c.name));
    for (const [name, definition] of Object.entries(columns)) {
      if (!existing.has(name)) {
        console.warn(`[perguntez] adicionando coluna ausente ${table}.${name}`);
        await env.DB.prepare(`ALTER TABLE ${quoteIdent(table)} ADD COLUMN ${quoteIdent(name)} ${definition}`).run();
      }
    }
  }

  // Compatibilidade com bancos antigos: users pode ter username como PRIMARY KEY
  // e não possuir id. Primeiro criamos o índice UNIQUE (NULLs são permitidos);
  // só depois preenchemos os IDs. A ordem é importante porque tabelas antigas,
  // como sessions, já podem ter uma FK apontando para users(id). Sem o índice,
  // o UPDATE pode falhar com "foreign key mismatch".
  await env.DB.prepare(
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_id_unique ON users(id)"
  ).run();
  await env.DB.prepare("UPDATE users SET id = rowid WHERE id IS NULL").run();

  // Em tabelas antigas, novos INSERTs não preenchem a coluna id adicionada.
  // Este trigger atribui o rowid como id antes das consultas seguintes do cadastro.
  await env.DB.prepare(`
    CREATE TRIGGER IF NOT EXISTS trg_users_assign_id
    AFTER INSERT ON users
    WHEN NEW.id IS NULL
    BEGIN
      UPDATE users SET id = rowid WHERE username = NEW.username;
    END
  `).run();

  const userCols = await tableColumns(env, "users");
  legacyUserColumns = userCols
    .filter((c) => c.notnull && c.dflt_value === null && !c.pk && !(c.name in REQUIRED_COLUMNS.users))
    .map((c) => c.name);

  // Sessões são descartáveis: se a tabela antiga tiver outro formato, ela é recriada
  // (no máximo desloga quem estava logado; nenhum usuário ou publicação é afetado).
  const sessionCols = await tableColumns(env, "sessions");
  const names = new Set(sessionCols.map((c) => c.name));
  const incompatible = SESSION_COLUMNS.some((c) => !names.has(c)) ||
    sessionCols.some((c) => c.notnull && c.dflt_value === null && !c.pk && !SESSION_COLUMNS.includes(c.name));
  if (incompatible) {
    console.warn("[perguntez] tabela sessions incompatível; recriando");
    await env.DB.batch([env.DB.prepare("DROP TABLE IF EXISTS sessions"), env.DB.prepare(TABLES[1])]);
  }

  for (const sql of INDEXES) {
    try { await env.DB.prepare(sql).run(); }
    catch (e) { console.warn("[perguntez] índice não criado:", sql, e && e.message); }
  }

  // As contas listadas em ADMIN_USERNAMES recebem o papel de administrador.
  // Em um banco novo, registre primeiro esse nome de usuário pela tela de cadastro.
  const admins = adminUsernames(env);
  if (admins.length) {
    await env.DB.prepare(
      `UPDATE users SET is_admin = 1 WHERE is_admin = 0 AND lower(username) IN (${admins.map(() => "?").join(",")})`
    ).bind(...admins).run();
  }
}

function ensureSchema(env) {
  if (!schemaReady) {
    schemaReady = migrateSchema(env).catch((e) => { schemaReady = null; throw e; });
  }
  return schemaReady;
}

/* ------------------------------ Sessões ------------------------------ */

async function newSessionValues() {
  const token = randomHex(32);
  return {
    token,
    tokenHash: await sha256(token),
    expires: new Date(Date.now() + SESSION_DAYS * 86400000).toISOString(),
  };
}

async function createSession(userId, env) {
  const s = await newSessionValues();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(new Date().toISOString()),
    env.DB.prepare("INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)")
      .bind(userId, s.tokenHash, s.expires),
  ]);
  return s.token;
}

const isUniqueError = (e) => /UNIQUE constraint failed/i.test(String((e && e.message) || ""));

const validUsername = (v) => typeof v === "string" && /^[A-Za-z0-9_]{3,20}$/.test(v);
const positiveId = (v) => Number.isSafeInteger(v) && v > 0;

function publicUser(u) {
  return {
    id: u.id, username: u.username, email: u.email, sobre: u.sobre || "",
    created_at: u.created_at, foto_v: u.foto_v || 0, is_admin: !!u.is_admin,
  };
}

async function notify(env, userId, actorId, kind, questionId = null, answerId = null, text = "") {
  if (!userId || userId === actorId) return;
  await env.DB.prepare(
    "INSERT INTO notifications (user_id, actor_id, kind, question_id, answer_id, text) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(userId, actorId, kind, questionId, answerId, text).run();
}

/* ------------------------------ Rotas ------------------------------ */

async function handle(request, env, path, method) {
  /* ---------- Conta ---------- */
  if (method === "GET" && path === "/me") {
    const user = await currentUser(request, env);
    return json({ user: user ? publicUser(user) : null });
  }

  if (method === "POST" && path === "/cadastro") {
    const body = await readJson(request);
    const username = String(body.username || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!validUsername(username)) throw new HttpError(400, "Usuário deve ter de 3 a 20 caracteres: letras, números ou _.");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 254) throw new HttpError(400, "E-mail inválido.");
    if (password.length < 8 || password.length > 128) throw new HttpError(400, "A senha deve ter entre 8 e 128 caracteres.");

    const existing = await env.DB.prepare(
      "SELECT username, email FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE LIMIT 1"
    ).bind(username, email).first();
    if (existing) {
      const sameEmail = String(existing.email || "").toLowerCase() === email;
      throw new HttpError(409, sameEmail ? "Este e-mail já está cadastrado." : "Este nome de usuário já está em uso.");
    }

    const salt = randomHex(16);
    const hash = await passwordHash(password, salt);
    const now = new Date().toISOString();

    const columns = ["username", "email", "password_salt", "password_hash", "sobre", "is_admin", "created_at"];
    const values = [username, email, salt, hash, "", isAdminName(env, username) ? 1 : 0, now];
    for (const col of legacyUserColumns) {
      columns.push(col);
      values.push(/pass|senha/i.test(col) ? hash : "");
    }

    // Usuário + sessão na MESMA transação (D1 batch é atômico). Antes, se a criação
    // da sessão falhasse, o usuário ficava salvo "pela metade" e a próxima tentativa
    // retornava "já cadastrado" sem a pessoa conseguir entrar.
    const session = await newSessionValues();
    try {
      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO users (${columns.map(quoteIdent).join(", ")}) VALUES (${columns.map(() => "?").join(", ")})`
        ).bind(...values),
        env.DB.prepare(
          "INSERT INTO sessions (user_id, token_hash, expires_at) SELECT id, ?, ? FROM users WHERE email = ? COLLATE NOCASE"
        ).bind(session.tokenHash, session.expires, email),
      ]);
    } catch (e) {
      if (isUniqueError(e)) throw new HttpError(409, "Este nome de usuário ou e-mail já está cadastrado.");
      throw e;
    }

    const user = await env.DB.prepare(
      "SELECT id, username, email, sobre, created_at, is_admin, 0 AS foto_v FROM users WHERE email = ? COLLATE NOCASE"
    ).bind(email).first();
    return json({ ok: true, user: publicUser(user) }, 201, { "Set-Cookie": cookieHeader(session.token, SESSION_DAYS * 86400) });
  }

  if (method === "POST" && path === "/login") {
    const body = await readJson(request);
    const identifier = String(body.username || "").trim();
    const password = String(body.password || "");
    if (!identifier || !password) throw new HttpError(400, "Informe usuário/e-mail e senha.");
    const user = await env.DB.prepare(`
      SELECT id, username, email, sobre, created_at, is_admin, password_salt, password_hash,
             CASE WHEN foto IS NULL OR foto = '' THEN 0 ELSE length(foto) END AS foto_v
      FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE LIMIT 1
    `).bind(identifier, identifier).first();
    if (!user) throw new HttpError(401, "Usuário ou senha inválidos.");
    let ok = safeEqual(await passwordHash(password, user.password_salt), user.password_hash);
    if (!ok) {
      // Contas criadas pela versão antiga (210.000 iterações), se houver: valida e migra o hash.
      try { ok = safeEqual(await passwordHash(password, user.password_salt, 210000), user.password_hash); } catch { ok = false; }
      if (ok) {
        await env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?")
          .bind(await passwordHash(password, user.password_salt), user.id).run();
      }
    }
    if (!ok) throw new HttpError(401, "Usuário ou senha inválidos.");
    const token = await createSession(user.id, env);
    return json({ ok: true, user: publicUser(user) }, 200, { "Set-Cookie": cookieHeader(token, SESSION_DAYS * 86400) });
  }

  if (method === "POST" && path === "/logout") {
    const token = getCookie(request, "pq_session");
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(token)).run();
    return json({ ok: true }, 200, { "Set-Cookie": cookieHeader("", 0) });
  }

  /* ---------- Perfis ---------- */
  if (method === "GET" && path === "/usuarios") {
    const { results } = await env.DB.prepare(`
      SELECT u.username, u.sobre, u.created_at, u.is_admin,
             CASE WHEN u.foto IS NULL OR u.foto = '' THEN 0 ELSE length(u.foto) END AS foto_v,
             (SELECT COUNT(*) FROM questions q WHERE q.user_id = u.id AND q.anonima = 0) AS perguntas,
             (SELECT COUNT(*) FROM answers a WHERE a.user_id = u.id) AS respostas
      FROM users u ORDER BY u.id LIMIT 5000
    `).all();
    return json({ users: results });
  }

  const fotoMatch = path.match(/^\/usuarios\/([A-Za-z0-9_]{3,20})\/foto$/);
  if (method === "GET" && fotoMatch) {
    const row = await env.DB.prepare("SELECT foto FROM users WHERE username = ? COLLATE NOCASE").bind(fotoMatch[1]).first();
    const m = row && typeof row.foto === "string" && row.foto.match(/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/);
    if (!m) return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
    const bin = atob(m[2]);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new Response(bytes, { headers: {
      "Content-Type": m[1],
      "Cache-Control": "public, max-age=86400",
      "X-Content-Type-Options": "nosniff",
    }});
  }

  if (method === "POST" && path === "/perfil") {
    const user = await requireUser(request, env, "Faça login para editar seu perfil.");
    const body = await readJson(request);
    const updates = [], values = [];
    if (body.sobre !== undefined) {
      const sobre = String(body.sobre || "").trim();
      if (sobre.length > 600) throw new HttpError(400, "O texto \"Sobre mim\" pode ter no máximo 600 caracteres.");
      updates.push("sobre = ?"); values.push(sobre);
    }
    if (body.foto !== undefined) {
      const foto = body.foto === null ? null : String(body.foto);
      if (foto !== null && (foto.length > MAX_FOTO_CHARS || !/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(foto))) {
        throw new HttpError(400, "Foto inválida ou muito grande.");
      }
      updates.push("foto = ?"); values.push(foto);
    }
    if (!updates.length) throw new HttpError(400, "Nada para atualizar.");
    await env.DB.prepare(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`).bind(...values, user.id).run();
    const fresh = await currentUser(request, env);
    return json({ ok: true, user: publicUser(fresh) });
  }

  /* ---------- Perguntas e respostas (feed público compartilhado) ---------- */
  if (method === "GET" && path === "/perguntas") {
    const viewer = await currentUser(request, env);
    const viewerId = viewer ? viewer.id : -1;
    const recent = "SELECT id FROM questions ORDER BY id DESC LIMIT 300";
    const [qs, ans, likes, comments] = await env.DB.batch([
      env.DB.prepare(`SELECT id, user_id, titulo, categoria, autor, anonima, views, descricao, created_at
                      FROM questions WHERE id IN (${recent}) ORDER BY id DESC`),
      env.DB.prepare(`SELECT id, question_id, user_id, autor, texto, votes, melhor, created_at
                      FROM answers WHERE question_id IN (${recent})
                      ORDER BY melhor DESC, votes DESC, id ASC`),
      env.DB.prepare(`SELECT target_type, target_id,
                             SUM(reaction = 'like') AS likes, SUM(reaction = 'dislike') AS dislikes
                      FROM likes GROUP BY target_type, target_id`),
      env.DB.prepare(`SELECT c.id, c.answer_id, c.user_id, c.text, c.created_at, u.username
                      FROM comments c JOIN users u ON u.id = c.user_id
                      JOIN answers a ON a.id = c.answer_id
                      WHERE a.question_id IN (${recent}) ORDER BY c.id`),
    ]);

    const likeMap = new Map(likes.results.map((l) => [l.target_type + ":" + l.target_id, l]));
    const commentsByAnswer = new Map();
    for (const c of comments.results) {
      if (!commentsByAnswer.has(c.answer_id)) commentsByAnswer.set(c.answer_id, []);
      commentsByAnswer.get(c.answer_id).push({ id: c.id, a: c.username, x: c.text, tempo: c.created_at, mine: c.user_id === viewerId });
    }

    const byId = new Map();
    for (const q of qs.results) {
      const mine = q.user_id === viewerId;
      const l = likeMap.get("question:" + q.id) || {};
      byId.set(q.id, {
        id: q.id, t: q.titulo, c: q.categoria,
        a: q.anonima ? "Anônimo" : q.autor,
        // Em perguntas anônimas o autor real nunca é enviado a terceiros.
        autor: q.anonima ? (mine ? q.autor : null) : q.autor,
        anonima: !!q.anonima, mine,
        tempo: q.created_at, v: q.views, d: q.descricao,
        gostei: Number(l.likes || 0), naoGostei: Number(l.dislikes || 0),
        r: [],
      });
    }
    for (const a of ans.results) {
      const q = byId.get(a.question_id);
      if (!q) continue;
      const l = likeMap.get("answer:" + a.id) || {};
      q.r.push({
        id: a.id, a: a.autor, tempo: a.created_at, x: a.texto,
        n: Number(a.votes || 0) + Number(l.likes || 0), dn: Number(l.dislikes || 0), m: a.melhor,
        mine: a.user_id === viewerId,
        comentarios: commentsByAnswer.get(a.id) || [],
      });
    }
    return json({ q: [...byId.values()] });
  }

  if (method === "POST" && path === "/perguntas") {
    const user = await requireUser(request, env, "Faça login para publicar uma pergunta.");
    const body = await readJson(request);
    const titulo = String(body.t || "").trim();
    const categoria = String(body.c || "").trim();
    const descricao = String(body.d || "").trim();
    const anonima = body.anonima ? 1 : 0;
    if (titulo.length < 8 || titulo.length > 180) throw new HttpError(400, "A pergunta deve ter de 8 a 180 caracteres.");
    if (!categoria || categoria.length > 60) throw new HttpError(400, "Categoria inválida.");
    if (descricao.length > 5000) throw new HttpError(400, "A descrição ultrapassa 5.000 caracteres.");
    if (anonima) {
      const limite = await env.DB.prepare(
        "SELECT COUNT(*) AS total FROM questions WHERE user_id = ? AND anonima = 1 AND date(created_at, '-3 hours') = date('now', '-3 hours')"
      ).bind(user.id).first();
      if ((limite?.total || 0) >= 3) throw new HttpError(429, "Você atingiu o limite de 3 perguntas anônimas por dia.");
    }
    const result = await env.DB.prepare(
      "INSERT INTO questions (user_id, titulo, categoria, autor, descricao, anonima) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(user.id, titulo, categoria, user.username, descricao, anonima).run();
    return json({ ok: true, id: result.meta.last_row_id }, 201);
  }

  if (method === "POST" && path === "/respostas") {
    const user = await requireUser(request, env, "Faça login para responder.");
    const body = await readJson(request);
    const questionId = Number(body.question_id);
    const texto = String(body.x || "").trim();
    if (!positiveId(questionId)) throw new HttpError(400, "Pergunta inválida.");
    if (texto.length < 3 || texto.length > 5000) throw new HttpError(400, "A resposta deve ter de 3 a 5.000 caracteres.");
    const q = await env.DB.prepare("SELECT id, user_id FROM questions WHERE id = ?").bind(questionId).first();
    if (!q) throw new HttpError(404, "Pergunta não encontrada.");
    const result = await env.DB.prepare(
      "INSERT INTO answers (question_id, user_id, autor, texto) VALUES (?, ?, ?, ?)"
    ).bind(questionId, user.id, user.username, texto).run();
    await notify(env, q.user_id, user.id, "answer", questionId, result.meta.last_row_id);
    return json({ ok: true, id: result.meta.last_row_id }, 201);
  }

  const viewMatch = path.match(/^\/perguntas\/(\d+)\/visualizacao$/);
  if (method === "POST" && viewMatch) {
    const result = await env.DB.prepare("UPDATE questions SET views = views + 1 WHERE id = ?").bind(Number(viewMatch[1])).run();
    if (!result.meta.changes) throw new HttpError(404, "Pergunta não encontrada.");
    return json({ ok: true });
  }

  /* ---------- Recursos sociais ---------- */
  if (method === "GET" && path === "/social") {
    const user = await requireUser(request, env, "Faça login para carregar sua rede.");
    const [follows, reactions, notifications, messages] = await env.DB.batch([
      env.DB.prepare(`SELECT u.username AS follower, v.username AS following
                      FROM follows f JOIN users u ON u.id = f.follower_id JOIN users v ON v.id = f.following_id`),
      env.DB.prepare(`SELECT target_type, target_id, reaction FROM likes WHERE user_id = ?`).bind(user.id),
      env.DB.prepare(`SELECT n.id, n.kind, n.question_id, n.answer_id, n.text, n.is_read, n.created_at,
                             actor.username AS actor, q.titulo AS question
                      FROM notifications n JOIN users actor ON actor.id = n.actor_id
                      LEFT JOIN questions q ON q.id = n.question_id
                      WHERE n.user_id = ? ORDER BY n.id DESC LIMIT 200`).bind(user.id),
      env.DB.prepare(`SELECT m.id, m.text, m.created_at, m.is_read, s.username AS sender, r.username AS receiver
                      FROM messages m JOIN users s ON s.id = m.sender_id JOIN users r ON r.id = m.receiver_id
                      WHERE m.sender_id = ? OR m.receiver_id = ? ORDER BY m.id DESC LIMIT 1000`).bind(user.id, user.id),
    ]);
    return json({
      follows: follows.results,
      reactions: reactions.results,
      notifications: notifications.results,
      messages: messages.results.reverse(),
    });
  }

  if (method === "POST" && path === "/social/like") {
    const user = await requireUser(request, env, "Faça login para curtir.");
    const b = await readJson(request);
    const type = String(b.target_type || ""), id = Number(b.target_id), reaction = String(b.reaction || "");
    if (!["question", "answer"].includes(type) || !positiveId(id) || !["like", "dislike", ""].includes(reaction)) {
      throw new HttpError(400, "Reação inválida.");
    }
    const target = type === "question"
      ? await env.DB.prepare("SELECT id AS question_id, user_id FROM questions WHERE id = ?").bind(id).first()
      : await env.DB.prepare("SELECT question_id, user_id FROM answers WHERE id = ?").bind(id).first();
    if (!target) throw new HttpError(404, "Publicação não encontrada.");
    const old = await env.DB.prepare("SELECT reaction FROM likes WHERE user_id = ? AND target_type = ? AND target_id = ?")
      .bind(user.id, type, id).first();
    let current = reaction;
    if (!reaction || (old && old.reaction === reaction)) {
      await env.DB.prepare("DELETE FROM likes WHERE user_id = ? AND target_type = ? AND target_id = ?").bind(user.id, type, id).run();
      current = "";
    } else {
      await env.DB.prepare(`INSERT INTO likes (user_id, target_type, target_id, reaction) VALUES (?, ?, ?, ?)
                            ON CONFLICT(user_id, target_type, target_id) DO UPDATE SET reaction = excluded.reaction`)
        .bind(user.id, type, id, reaction).run();
    }
    if (current === "like" && !(old && old.reaction === "like")) {
      await notify(env, target.user_id, user.id, "like", target.question_id, type === "answer" ? id : null);
    }
    return json({ ok: true, reaction: current });
  }

  if (method === "POST" && path === "/social/comment") {
    const user = await requireUser(request, env, "Faça login para comentar.");
    const b = await readJson(request);
    const id = Number(b.answer_id), text = String(b.text || "").trim();
    if (!positiveId(id) || text.length < 2 || text.length > 1000) throw new HttpError(400, "Comentário inválido (2 a 1.000 caracteres).");
    const a = await env.DB.prepare("SELECT question_id, user_id FROM answers WHERE id = ?").bind(id).first();
    if (!a) throw new HttpError(404, "Resposta não encontrada.");
    const result = await env.DB.prepare("INSERT INTO comments (answer_id, user_id, text) VALUES (?, ?, ?)").bind(id, user.id, text).run();
    await notify(env, a.user_id, user.id, "comment", a.question_id, id, text.slice(0, 200));
    return json({ ok: true, id: result.meta.last_row_id }, 201);
  }

  if (method === "POST" && path === "/social/follow") {
    const user = await requireUser(request, env, "Faça login para seguir pessoas.");
    const b = await readJson(request);
    const target = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE")
      .bind(String(b.username || "").trim()).first();
    if (!target) throw new HttpError(404, "Usuário não encontrado.");
    if (target.id === user.id) throw new HttpError(400, "Você não pode seguir a si mesmo.");
    const old = await env.DB.prepare("SELECT 1 AS ok FROM follows WHERE follower_id = ? AND following_id = ?").bind(user.id, target.id).first();
    if (old) {
      await env.DB.prepare("DELETE FROM follows WHERE follower_id = ? AND following_id = ?").bind(user.id, target.id).run();
    } else {
      await env.DB.prepare("INSERT INTO follows (follower_id, following_id) VALUES (?, ?)").bind(user.id, target.id).run();
      await notify(env, target.id, user.id, "follow");
    }
    return json({ ok: true, following: !old });
  }

  if (method === "POST" && path === "/social/message") {
    const user = await requireUser(request, env, "Faça login para enviar mensagens.");
    const b = await readJson(request);
    const text = String(b.text || "").trim();
    const target = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE")
      .bind(String(b.to || "").trim()).first();
    if (!target) throw new HttpError(404, "Este usuário não existe no Perguntez.");
    if (target.id === user.id) throw new HttpError(400, "Você não pode enviar mensagem para si mesmo.");
    if (!text || text.length > 1000) throw new HttpError(400, "A mensagem deve ter de 1 a 1.000 caracteres.");
    const result = await env.DB.prepare("INSERT INTO messages (sender_id, receiver_id, text) VALUES (?, ?, ?)").bind(user.id, target.id, text).run();
    await notify(env, target.id, user.id, "message", null, null, "Enviou uma mensagem");
    return json({ ok: true, id: result.meta.last_row_id }, 201);
  }

  if (method === "POST" && path === "/social/message/read") {
    const user = await requireUser(request, env, "Não autenticado.");
    const b = await readJson(request);
    const from = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE")
      .bind(String(b.from || "").trim()).first();
    if (!from) return json({ ok: true });
    await env.DB.prepare("UPDATE messages SET is_read = 1 WHERE receiver_id = ? AND sender_id = ? AND is_read = 0")
      .bind(user.id, from.id).run();
    return json({ ok: true });
  }

  // Assinatura barata do estado da rede: o navegador consulta a cada poucos segundos
  // e só baixa tudo de novo quando algo mudou (nova pergunta, resposta, curtida, mensagem...).
  if (method === "GET" && path === "/pulso") {
    const user = await currentUser(request, env);
    const uid = user ? user.id : 0;
    const r = await env.DB.prepare(`SELECT
        (SELECT COUNT(*) || ':' || IFNULL(MAX(id),0) FROM questions) AS q,
        (SELECT COUNT(*) || ':' || IFNULL(MAX(id),0) || ':' || IFNULL(SUM(melhor),0) FROM answers) AS a,
        (SELECT COUNT(*) || ':' || IFNULL(MAX(id),0) FROM comments) AS c,
        (SELECT COUNT(*) || ':' || IFNULL(SUM(reaction = 'like'),0) FROM likes) AS l,
        (SELECT COUNT(*) FROM follows) AS f,
        (SELECT COUNT(*) || ':' || IFNULL(SUM(length(sobre)),0) || ':' || IFNULL(SUM(length(foto)),0) FROM users) AS u,
        (SELECT COUNT(*) || ':' || IFNULL(MAX(id),0) || ':' || IFNULL(SUM(is_read),0) FROM messages WHERE sender_id = ?1 OR receiver_id = ?1) AS m,
        (SELECT COUNT(*) || ':' || IFNULL(MAX(id),0) || ':' || IFNULL(SUM(is_read),0) FROM notifications WHERE user_id = ?1) AS n`)
      .bind(uid).first();
    return json({ p: [uid, r.q, r.a, r.c, r.l, r.f, r.u, r.m, r.n].join("|") });
  }

  if (method === "POST" && path === "/social/read") {
    const user = await requireUser(request, env, "Não autenticado.");
    await env.DB.prepare("UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0").bind(user.id).run();
    return json({ ok: true });
  }

  /* ---------- Moderação: autor ou administrador ---------- */
  const delQuestion = path.match(/^\/perguntas\/(\d+)\/excluir$/);
  if (method === "POST" && delQuestion) {
    const user = await requireUser(request, env);
    const id = Number(delQuestion[1]);
    const q = await env.DB.prepare("SELECT id, user_id FROM questions WHERE id = ?").bind(id).first();
    if (!q) throw new HttpError(404, "Pergunta não encontrada.");
    if (q.user_id !== user.id && !user.is_admin) throw new HttpError(403, "Você só pode excluir suas próprias perguntas.");
    const answersOf = "SELECT id FROM answers WHERE question_id = ?";
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM likes WHERE (target_type = 'question' AND target_id = ?) OR (target_type = 'answer' AND target_id IN (${answersOf}))`).bind(id, id),
      env.DB.prepare(`DELETE FROM comments WHERE answer_id IN (${answersOf})`).bind(id),
      env.DB.prepare(`DELETE FROM notifications WHERE question_id = ? OR answer_id IN (${answersOf})`).bind(id, id),
      env.DB.prepare("DELETE FROM answers WHERE question_id = ?").bind(id),
      env.DB.prepare("DELETE FROM questions WHERE id = ?").bind(id),
    ]);
    return json({ ok: true });
  }

  const delAnswer = path.match(/^\/respostas\/(\d+)\/excluir$/);
  if (method === "POST" && delAnswer) {
    const user = await requireUser(request, env);
    const id = Number(delAnswer[1]);
    const a = await env.DB.prepare("SELECT id, user_id FROM answers WHERE id = ?").bind(id).first();
    if (!a) throw new HttpError(404, "Resposta não encontrada.");
    if (a.user_id !== user.id && !user.is_admin) throw new HttpError(403, "Você só pode excluir suas próprias respostas.");
    await env.DB.batch([
      env.DB.prepare("DELETE FROM likes WHERE target_type = 'answer' AND target_id = ?").bind(id),
      env.DB.prepare("DELETE FROM comments WHERE answer_id = ?").bind(id),
      env.DB.prepare("DELETE FROM notifications WHERE answer_id = ?").bind(id),
      env.DB.prepare("DELETE FROM answers WHERE id = ?").bind(id),
    ]);
    return json({ ok: true });
  }

  const delComment = path.match(/^\/comentarios\/(\d+)\/excluir$/);
  if (method === "POST" && delComment) {
    const user = await requireUser(request, env);
    const id = Number(delComment[1]);
    const c = await env.DB.prepare("SELECT id, user_id FROM comments WHERE id = ?").bind(id).first();
    if (!c) throw new HttpError(404, "Comentário não encontrado.");
    if (c.user_id !== user.id && !user.is_admin) throw new HttpError(403, "Você só pode excluir seus próprios comentários.");
    await env.DB.prepare("DELETE FROM comments WHERE id = ?").bind(id).run();
    return json({ ok: true });
  }

  const bestAnswer = path.match(/^\/respostas\/(\d+)\/melhor$/);
  if (method === "POST" && bestAnswer) {
    const user = await requireUser(request, env);
    const id = Number(bestAnswer[1]);
    const a = await env.DB.prepare(
      "SELECT a.id, a.user_id, a.melhor, a.question_id, q.user_id AS question_owner FROM answers a JOIN questions q ON q.id = a.question_id WHERE a.id = ?"
    ).bind(id).first();
    if (!a) throw new HttpError(404, "Resposta não encontrada.");
    if (a.question_owner !== user.id && !user.is_admin) throw new HttpError(403, "Só quem perguntou pode escolher a melhor resposta.");
    const marcar = a.melhor ? 0 : 1;
    await env.DB.batch([
      env.DB.prepare("UPDATE answers SET melhor = 0 WHERE question_id = ?").bind(a.question_id),
      env.DB.prepare("UPDATE answers SET melhor = ? WHERE id = ?").bind(marcar, id),
    ]);
    if (marcar) await notify(env, a.user_id, user.id, "best", a.question_id, id, "Escolheu sua resposta como a melhor");
    return json({ ok: true, melhor: !!marcar });
  }

  /* ---------- Painel do administrador ---------- */
  if (method === "GET" && path === "/admin/resumo") {
    await requireAdmin(request, env);
    const [totals, users] = await env.DB.batch([
      env.DB.prepare(`SELECT
        (SELECT COUNT(*) FROM users) AS usuarios,
        (SELECT COUNT(*) FROM questions) AS perguntas,
        (SELECT COUNT(*) FROM answers) AS respostas,
        (SELECT COUNT(*) FROM comments) AS comentarios,
        (SELECT COUNT(*) FROM messages) AS mensagens,
        (SELECT COUNT(*) FROM sessions WHERE expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')) AS sessoes_ativas`),
      env.DB.prepare(`SELECT u.username, u.email, u.is_admin, u.created_at,
                             (SELECT COUNT(*) FROM questions q WHERE q.user_id = u.id) AS perguntas,
                             (SELECT COUNT(*) FROM answers a WHERE a.user_id = u.id) AS respostas
                      FROM users u ORDER BY u.id DESC LIMIT 1000`),
    ]);
    return json({ totais: totals.results[0] || {}, usuarios: users.results });
  }

  const adminUser = path.match(/^\/admin\/usuarios\/([A-Za-z0-9_]{1,40})\/(excluir|admin)$/);
  if (method === "POST" && adminUser) {
    const admin = await requireAdmin(request, env);
    const target = await env.DB.prepare("SELECT id, username, is_admin FROM users WHERE username = ? COLLATE NOCASE").bind(adminUser[1]).first();
    if (!target) throw new HttpError(404, "Usuário não encontrado.");
    if (target.id === admin.id) throw new HttpError(400, "Você não pode alterar a sua própria conta por aqui.");

    if (adminUser[2] === "admin") {
      const novo = target.is_admin ? 0 : 1;
      if (!novo && isAdminName(env, target.username)) throw new HttpError(400, "Este administrador é fixo na configuração (ADMIN_USERNAMES).");
      await env.DB.prepare("UPDATE users SET is_admin = ? WHERE id = ?").bind(novo, target.id).run();
      return json({ ok: true, is_admin: !!novo });
    }

    if (target.is_admin) throw new HttpError(400, "Remova o cargo de administrador antes de excluir esta conta.");
    const u = target.id;
    const qOf = "SELECT id FROM questions WHERE user_id = ?";
    const aOf = `SELECT id FROM answers WHERE user_id = ? OR question_id IN (${qOf})`;
    await env.DB.batch([
      env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(u),
      env.DB.prepare("DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?").bind(u, u),
      env.DB.prepare("DELETE FROM follows WHERE follower_id = ? OR following_id = ?").bind(u, u),
      env.DB.prepare("DELETE FROM likes WHERE user_id = ?").bind(u),
      env.DB.prepare(`DELETE FROM likes WHERE target_type = 'answer' AND target_id IN (${aOf})`).bind(u, u),
      env.DB.prepare(`DELETE FROM likes WHERE target_type = 'question' AND target_id IN (${qOf})`).bind(u),
      env.DB.prepare(`DELETE FROM notifications WHERE user_id = ? OR actor_id = ? OR question_id IN (${qOf}) OR answer_id IN (${aOf})`).bind(u, u, u, u, u),
      env.DB.prepare(`DELETE FROM comments WHERE user_id = ? OR answer_id IN (${aOf})`).bind(u, u, u),
      env.DB.prepare(`DELETE FROM answers WHERE user_id = ? OR question_id IN (${qOf})`).bind(u, u),
      env.DB.prepare("DELETE FROM questions WHERE user_id = ?").bind(u),
      env.DB.prepare("DELETE FROM users WHERE id = ?").bind(u),
    ]);
    return json({ ok: true });
  }

  /* ---------- Diagnóstico ---------- */
  if (method === "GET" && path === "/status") {
    const row = await env.DB.prepare("SELECT COUNT(*) AS usuarios FROM users").first();
    return json({ ok: true, banco: "conectado", usuarios: row ? row.usuarios : 0 });
  }

  throw new HttpError(404, "Rota não encontrada.");
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) return handleApi(request, env);
    return env.ASSETS.fetch(request);
  },
};

async function handleApi(request, env) {
  cookieSameSite = env.COOKIE_SAMESITE === "None" ? "None" : "Lax";
  const url = new URL(request.url);
  const path = (url.pathname.replace(/^\/api(?=\/|$)/, "") || "/").replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, { status: 204, headers: { "Allow": "GET, POST, OPTIONS", "Cache-Control": "no-store" } });
  }

  // Bloqueia requisições de escrita vindas de outros sites (proteção CSRF).
  if (method === "POST") {
    const origin = request.headers.get("Origin");
    let originHost = "";
    try { originHost = origin ? new URL(origin).host : ""; } catch { originHost = "invalid"; }
    const allowedHosts = [url.host, request.headers.get("X-Forwarded-Host")].filter(Boolean);
    if (origin && origin !== "null" && !allowedHosts.includes(originHost)) {
      return json({ error: "Origem não permitida." }, 403);
    }
  }

  if (!env.DB) return json({ error: "Banco D1 não configurado. Verifique o binding DB." }, 503);

  try {
    await ensureSchema(env);
  } catch (error) {
    console.error("[perguntez] falha ao preparar o banco:", error && error.stack || error);
    return json({ error: "Banco de dados indisponível no momento. Tente novamente em instantes." }, 503);
  }

  try {
    return await handle(request, env, path, method);
  } catch (error) {
    if (error instanceof HttpError) return json({ error: error.message }, error.status);
    // Mantém detalhes técnicos apenas nos logs e devolve uma orientação útil ao usuário.
    const detail = String((error && error.message) || error || "");
    console.error("[perguntez] erro interno:", error && error.stack || error);
    let message = "O servidor não conseguiu concluir esta ação. Tente novamente em instantes.";
    if (/UNIQUE constraint failed/i.test(detail)) {
      message = "Este nome de usuário ou e-mail já está cadastrado. Tente entrar ou use outros dados.";
      return json({ error: message }, 409);
    }
    if (/NOT NULL constraint failed/i.test(detail)) {
      message = "O banco D1 possui uma coluna obrigatória de uma versão antiga. A estrutura precisa ser atualizada antes do cadastro.";
      return json({ error: message }, 503);
    }
    if (/no such column|no such table/i.test(detail)) {
      message = "A estrutura do banco D1 está incompleta. Verifique a migração do Perguntez e tente novamente.";
      return json({ error: message }, 503);
    }
    return json({ error: message }, 500);
  }
}
