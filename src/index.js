const SESSION_TTL = 60 * 60 * 24 * 7;
const SESSION_TTL_MS = SESSION_TTL * 1000;

const LOGIN_WINDOW_MS = 60_000;
const LOGIN_MAX_ATTEMPTS = 5;

const JSON_MAX_BYTES = 1_000_000;
const MAX_MESSAGES = 300;          // 每个对话最多保留的消息数
const MAX_CONV_NAME = 80;
const MAX_MSG_NAME = 255;

const SAFE_INLINE_TYPES = new Set([
  'image/jpeg', 'image/jpg', 'image/png', 'image/gif',
  'image/webp', 'image/avif', 'image/bmp',
  'application/pdf',
]);

const encoder = new TextEncoder();

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extra },
  });

async function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const [ah, bh] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(a)),
    crypto.subtle.digest('SHA-256', encoder.encode(b)),
  ]);
  const A = new Uint8Array(ah), B = new Uint8Array(bh);
  let diff = 0;
  for (let i = 0; i < A.length; i++) diff |= A[i] ^ B[i];
  return diff === 0;
}

function parseTs(v, fallback = 0) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}

function isExpired(meta) {
  if (!meta || !meta.e) return false;
  const exp = parseTs(meta.e, 0);
  return exp > 0 && Date.now() > exp;
}

function safeMime(raw) {
  if (typeof raw !== 'string') return 'application/octet-stream';
  const clean = raw.toLowerCase().replace(/[\r\n\t]/g, '').trim();
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(clean)) {
    return 'application/octet-stream';
  }
  if (clean.length > 100) return 'application/octet-stream';
  return clean;
}

function safeDecode(s) {
  if (typeof s !== 'string') return '';
  try { return decodeURIComponent(s); } catch { return ''; }
}

async function safeJsonBody(request, maxBytes = JSON_MAX_BYTES) {
  const len = request.headers.get('Content-Length');
  if (len) {
    const n = parseInt(len, 10);
    if (Number.isFinite(n) && n > maxBytes) {
      throw new Response('payload too large', { status: 413 });
    }
  }
  try {
    const txt = await request.text();
    if (txt.length > maxBytes) {
      throw new Response('payload too large', { status: 413 });
    }
    return txt ? JSON.parse(txt) : {};
  } catch (e) {
    if (e instanceof Response) throw e;
    throw new Response('bad json', { status: 400 });
  }
}

function parseCookie(header, name) {
  if (!header) return null;
  const re = new RegExp('(?:^|;\\s*)' + name + '=([^;]*)');
  const m = header.match(re);
  return m ? m[1] : null;
}

const setCookie = (sid, maxAge) =>
  `sid=${sid}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;

async function getSession(env, request) {
  const sid = parseCookie(request.headers.get('Cookie'), 'sid');
  if (!sid || !/^[a-f0-9]{64}$/.test(sid)) return null;
  const key = 'session/' + sid;
  const obj = await env.BUCKET.head(key);
  if (!obj) return null;
  const exp = parseTs(obj.customMetadata?.exp, 0);
  if (exp <= 0 || Date.now() > exp) {
    await env.BUCKET.delete(key);
    return null;
  }
  return { sid, key, exp };
}

async function refreshSession(env, sess) {
  const newExp = Date.now() + SESSION_TTL_MS;
  if (newExp - sess.exp < SESSION_TTL_MS * 0.5) return null;
  await env.BUCKET.put(sess.key, '1', {
    customMetadata: { exp: String(newExp) },
  });
}

function clientIp(request) {
  return (
    request.headers.get('CF-Connecting-IP') ||
    (request.headers.get('X-Forwarded-For') || '').split(',')[0].trim() ||
    'unknown'
  );
}

async function loginRateLimit(env, ip) {
  const key = 'ratelimit/login/' + ip.replace(/[^a-fA-F0-9:.]/g, '_');
  const now = Date.now();
  let data = null;
  try {
    const obj = await env.BUCKET.get(key);
    if (obj) data = JSON.parse(await obj.text());
  } catch {}
  if (!data || typeof data !== 'object' || !Number.isFinite(data.r) || now > data.r) {
    data = { c: 0, r: now + LOGIN_WINDOW_MS };
  }
  data.c = (Number.isFinite(data.c) ? data.c : 0) + 1;
  if (data.c > LOGIN_MAX_ATTEMPTS) {
    const retryAfter = Math.max(1, Math.ceil((data.r - now) / 1000));
    return { blocked: true, retryAfter, key, data };
  }
  return { blocked: false, key, data };
}

async function recordAttempt(env, key, data) {
  await env.BUCKET.put(key, JSON.stringify(data), {
    customMetadata: { exp: String(data.r + 60_000) },
  });
}

async function* listAll(bucket, opts = {}) {
  let cursor;
  let pages = 0;
  do {
    const page = await bucket.list({ ...opts, cursor, limit: 1000 });
    for (const o of page.objects) yield o;
    cursor = page.truncated ? page.cursor : undefined;
    pages++;
    if (pages > 100) break;
  } while (cursor);
}

/* ---------- ID 校验 ---------- */
function isValidConvId(id) {
  return typeof id === 'string' && /^[a-f0-9]{16,32}$/.test(id);
}
function isValidMsgId(id) {
  return typeof id === 'string' && /^\d{10,16}-[a-f0-9]{8}$/.test(id);
}

/* ---------- 对话 ---------- */
async function listConversations(env) {
  const list = [];
  const gets = [];
  for await (const o of listAll(env.BUCKET, { prefix: 'conv/' })) {
    if (!o.key.endsWith('/meta')) continue;
    gets.push((async () => {
      const obj = await env.BUCKET.get(o.key);
      if (!obj) return;
      try { list.push(JSON.parse(await obj.text())); } catch {}
    })());
  }
  await Promise.all(gets);
  list.sort((a, b) => (b.updated || 0) - (a.updated || 0));
  return json({ conversations: list });
}

async function createConversation(env, request) {
  let body;
  try { body = await safeJsonBody(request); }
  catch (e) { return e instanceof Response ? e : json({ error: 'bad request' }, 400); }

  const rawName = typeof body.name === 'string' ? body.name : '';
  const name = (rawName.trim() || '新对话').slice(0, MAX_CONV_NAME);
  const now = Date.now();
  const id = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
  const conv = { id, name, created: now, updated: now };

  await env.BUCKET.put(`conv/${id}/meta`, JSON.stringify(conv));
  return json({ conversation: conv });
}

async function updateConvUpdated(env, convId, ts) {
  const key = `conv/${convId}/meta`;
  const obj = await env.BUCKET.get(key);
  if (!obj) return;
  try {
    const data = JSON.parse(await obj.text());
    data.updated = ts;
    await env.BUCKET.put(key, JSON.stringify(data));
  } catch {}
}

async function deleteConversation(env, convId) {
  const fileKeys = [];
  const deletes = [];
  for await (const o of listAll(env.BUCKET, { prefix: `conv/${convId}/` })) {
    if (o.key.includes('/msg/')) {
      const meta = o.customMetadata || {};
      if (meta.t === 'file' && meta.k) fileKeys.push(meta.k);
    }
    deletes.push(env.BUCKET.delete(o.key));
  }
  await Promise.all(deletes);
  if (fileKeys.length) {
    await Promise.all(fileKeys.map(k => env.BUCKET.delete(k).catch(() => {})));
  }
  return json({ ok: true });
}

/* ---------- 消息 ---------- */
async function listMessages(env, convId) {
  const arr = [];
  for await (const o of listAll(env.BUCKET, { prefix: `conv/${convId}/msg/` })) {
    arr.push(o);
  }
  arr.sort((a, b) => a.key.localeCompare(b.key));

  const recent = arr.length > MAX_MESSAGES ? arr.slice(-MAX_MESSAGES) : arr;
  const prefix = `conv/${convId}/msg/`;

  const messages = [];
  for (const o of recent) {
    const meta = o.customMetadata || {};
    const id = o.key.slice(prefix.length);
    const ts = parseTs(meta.ts, parseTs(id.split('-')[0], 0));

    if (meta.t === 'file') {
      messages.push({
        id, t: 'file', ts,
        k: meta.k || '',
        n: meta.n || '',
        s: parseTs(meta.s, 0),
        m: meta.m || '',
        e: parseTs(meta.e, 0),
      });
    } else {
      const obj = await env.BUCKET.get(o.key);
      const v = obj ? await obj.text() : '';
      messages.push({ id, t: 'text', ts, v });
    }
  }
  return json({ messages });
}

async function createMessage(env, request, convId) {
  // 确认对话存在
  const metaObj = await env.BUCKET.head(`conv/${convId}/meta`);
  if (!metaObj) return json({ error: 'conversation not found' }, 404);

  let body;
  try { body = await safeJsonBody(request); }
  catch (e) { return e instanceof Response ? e : json({ error: 'bad request' }, 400); }

  const now = Date.now();
  const msgId = `${now}-${crypto.randomUUID().replace(/-/g, '').slice(0, 8)}`;
  const key = `conv/${convId}/msg/${msgId}`;

  if (body.t === 'text') {
    const v = typeof body.v === 'string' ? body.v : '';
    if (!v) return json({ error: 'empty message' }, 400);
    if (v.length > 200_000) return json({ error: 'too long' }, 400);

    await env.BUCKET.put(key, v, {
      customMetadata: { t: 'text', ts: String(now) },
    });
  } else if (body.t === 'file') {
    const k = typeof body.k === 'string' ? body.k : '';
    if (!k || k.length > 100 || k.includes('/')) {
      return json({ error: 'bad file key' }, 400);
    }

    // 确认文件存在
    const fileObj = await env.BUCKET.head(k);
    if (!fileObj) return json({ error: 'file not found' }, 404);

    const rawName = typeof body.n === 'string' ? body.n : '';
    const name = (rawName.trim() || 'file').slice(0, MAX_MSG_NAME)
      .replace(/[\r\n\t]/g, ' ');
    const size = parseTs(body.s, fileObj.size || 0);
    const mime = safeMime(body.m);
    const exp = parseTs(body.e, 0);

    await env.BUCKET.put(key, '', {
      customMetadata: {
        t: 'file',
        ts: String(now),
        k,
        n: name,
        s: String(size),
        m: mime,
        e: exp > 0 ? String(exp) : '',
      },
    });
  } else {
    return json({ error: 'bad type' }, 400);
  }

  // 更新对话时间 + 裁剪超限消息
  await updateConvUpdated(env, convId, now).catch(() => {});
  await trimMessages(env, convId).catch(() => {});

  return json({ ok: true, id: msgId, ts: now });
}

async function trimMessages(env, convId) {
  const arr = [];
  for await (const o of listAll(env.BUCKET, { prefix: `conv/${convId}/msg/` })) {
    arr.push(o);
  }
  if (arr.length <= MAX_MESSAGES) return;
  arr.sort((a, b) => a.key.localeCompare(b.key));
  const toDelete = arr.slice(0, arr.length - MAX_MESSAGES);

  for (const o of toDelete) {
    const meta = o.customMetadata || {};
    if (meta.t === 'file' && meta.k) {
      await env.BUCKET.delete(meta.k).catch(() => {});
    }
    await env.BUCKET.delete(o.key).catch(() => {});
  }
}

async function deleteMessage(env, convId, msgId) {
  const key = `conv/${convId}/msg/${msgId}`;
  const obj = await env.BUCKET.head(key);
  if (!obj) return json({ error: 'not found' }, 404);
  const meta = obj.customMetadata || {};
  if (meta.t === 'file' && meta.k) {
    await env.BUCKET.delete(meta.k).catch(() => {});
  }
  await env.BUCKET.delete(key);
  return json({ ok: true });
}

async function patchMessage(env, request, convId, msgId) {
  const key = `conv/${convId}/msg/${msgId}`;
  const obj = await env.BUCKET.head(key);
  if (!obj) return json({ error: 'not found' }, 404);
  const meta = obj.customMetadata || {};
  if (meta.t !== 'file') {
    return json({ error: 'only file messages can be renamed' }, 400);
  }

  let body;
  try { body = await safeJsonBody(request); }
  catch (e) { return e instanceof Response ? e : json({ error: 'bad request' }, 400); }

  const rawName = body.n;
  if (typeof rawName !== 'string' || !rawName.trim() || rawName.length > MAX_MSG_NAME) {
    return json({ error: 'invalid name' }, 400);
  }
  const name = rawName.trim().replace(/[\r\n\t]/g, ' ');

  const newMeta = { ...meta, n: name };

  // 消息对象的 body 是空的，直接重写元数据即可
  await env.BUCKET.put(key, '', { customMetadata: newMeta });

  // 同步更新底层文件对象的名称
  if (meta.k) {
    try {
      const fobj = await env.BUCKET.get(meta.k);
      if (fobj) {
        const fmeta = { ...(fobj.customMetadata || {}), n: name };
        await env.BUCKET.put(meta.k, fobj.body, {
          customMetadata: fmeta,
          httpMetadata: fobj.httpMetadata,
        });
      }
    } catch {}
  }

  return json({ ok: true, n: name });
}

/* ============================================================ */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    /* ---------- 静态资源 ---------- */
    if (!path.startsWith('/api/')) {
      const res = await env.ASSETS.fetch(request);
      const headers = new Headers(res.headers);
      headers.set('X-Content-Type-Options', 'nosniff');
      headers.set('Referrer-Policy', 'no-referrer');
      headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
      headers.set('X-Frame-Options', 'DENY');
      headers.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
      headers.set('Content-Security-Policy', [
        "default-src 'self'",
        "img-src 'self' data: blob:",
        "style-src 'self' 'unsafe-inline'",
        "script-src 'self' 'unsafe-inline'",
        "connect-src 'self'",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
      ].join('; '));
      return new Response(res.body, {
        status: res.status,
        statusText: res.statusText,
        headers,
      });
    }

    /* ---------- 登录 / 登出 / 会话 ---------- */
    if (path === '/api/login' && request.method === 'POST') {
      const ip = clientIp(request);
      const rl = await loginRateLimit(env, ip);
      if (rl.blocked) {
        return json(
          { error: 'too many attempts', retryAfter: rl.retryAfter },
          429,
          { 'Retry-After': String(rl.retryAfter) }
        );
      }

      let body;
      try { body = await safeJsonBody(request); }
      catch (e) {
        await recordAttempt(env, rl.key, rl.data);
        return e instanceof Response ? e : json({ error: 'bad request' }, 400);
      }

      const { password } = body;
      if (!password || typeof password !== 'string' || password.length > 256) {
        await recordAttempt(env, rl.key, rl.data);
        return json({ error: 'unauthorized' }, 401);
      }

      if (!(await timingSafeEqual(password, env.ACCESS_TOKEN))) {
        await recordAttempt(env, rl.key, rl.data);
        return json({ error: 'unauthorized' }, 401);
      }

      await env.BUCKET.delete(rl.key).catch(() => {});

      const sid =
        crypto.randomUUID().replace(/-/g, '') +
        crypto.randomUUID().replace(/-/g, '');

      await env.BUCKET.put('session/' + sid, '1', {
        customMetadata: { exp: String(Date.now() + SESSION_TTL_MS) },
      });

      return json({ ok: true }, 200, { 'Set-Cookie': setCookie(sid, SESSION_TTL) });
    }

    if (path === '/api/logout' && request.method === 'POST') {
      const sess = await getSession(env, request);
      if (sess) await env.BUCKET.delete(sess.key);
      return json({ ok: true }, 200, { 'Set-Cookie': setCookie('', 0) });
    }

    if (path === '/api/logout-all' && request.method === 'POST') {
      const sess = await getSession(env, request);
      if (!sess) return json({ error: 'unauthorized' }, 401);
      let count = 0;
      for await (const o of listAll(env.BUCKET, { prefix: 'session/' })) {
        await env.BUCKET.delete(o.key);
        count++;
      }
      return json({ ok: true, revoked: count }, 200, {
        'Set-Cookie': setCookie('', 0),
      });
    }

    if (path === '/api/session' && request.method === 'GET') {
      const sess = await getSession(env, request);
      return json({ ok: !!sess });
    }

    /* ---------- 认证 + 滑动续期 ---------- */
    const sess = await getSession(env, request);
    if (!sess) return json({ error: 'unauthorized' }, 401);
    ctx.waitUntil(refreshSession(env, sess).catch(() => {}));

    /* ---------- 对话 ---------- */
    if (path === '/api/conversations') {
      if (request.method === 'GET') return listConversations(env);
      if (request.method === 'POST') return createConversation(env, request);
      return json({ error: 'method not allowed' }, 405);
    }

    const convMatch = path.match(/^\/api\/conversations\/([^\/]+)$/);
    if (convMatch) {
      const convId = safeDecode(convMatch[1]);
      if (!isValidConvId(convId)) return json({ error: 'bad id' }, 400);
      if (request.method === 'DELETE') {
        return deleteConversation(env, convId);
      }
      return json({ error: 'method not allowed' }, 405);
    }

    /* ---------- 消息集合 ---------- */
    const msgsMatch = path.match(/^\/api\/conversations\/([^\/]+)\/messages$/);
    if (msgsMatch) {
      const convId = safeDecode(msgsMatch[1]);
      if (!isValidConvId(convId)) return json({ error: 'bad id' }, 400);
      if (request.method === 'GET') return listMessages(env, convId);
      if (request.method === 'POST') return createMessage(env, request, convId);
      return json({ error: 'method not allowed' }, 405);
    }

    /* ---------- 单条消息 ---------- */
    const msgMatch = path.match(/^\/api\/conversations\/([^\/]+)\/messages\/([^\/]+)$/);
    if (msgMatch) {
      const convId = safeDecode(msgMatch[1]);
      const msgId = safeDecode(msgMatch[2]);
      if (!isValidConvId(convId) || !isValidMsgId(msgId)) {
        return json({ error: 'bad id' }, 400);
      }
      if (request.method === 'DELETE') {
        return deleteMessage(env, convId, msgId);
      }
      if (request.method === 'PATCH') {
        return patchMessage(env, request, convId, msgId);
      }
      return json({ error: 'method not allowed' }, 405);
    }

    /* ---------- 文件上传 ---------- */
    if (path === '/api/files' && request.method === 'POST') {
      if (!request.body) return json({ error: 'no body' }, 400);

      const key = crypto.randomUUID();
      const rawName = request.headers.get('X-File-Name') || '';
      const name = safeDecode(rawName).slice(0, MAX_MSG_NAME).replace(/[\r\n\t]/g, ' ');
      const rawType = request.headers.get('X-File-Type') || '';
      const type = safeMime(rawType);
      const expiresSec = parseTs(request.headers.get('X-Expires'), 0);

      const meta = { n: name || 'unnamed', t: type };
      if (expiresSec > 0 && expiresSec <= 60 * 60 * 24 * 365) {
        meta.e = String(Date.now() + expiresSec * 1000);
      }

      await env.BUCKET.put(key, request.body, {
        customMetadata: meta,
        httpMetadata: { contentType: type },
      });

      return json({ key, name: meta.n, exp: meta.e ? parseTs(meta.e, 0) : 0 });
    }

    /* ---------- 文件下载 ---------- */
    if (path.startsWith('/api/files/') && request.method === 'GET') {
      const key = safeDecode(path.slice('/api/files/'.length));
      if (!key || key.length > 100 || key.includes('/')) {
        return json({ error: 'bad key' }, 400);
      }

      const obj = await env.BUCKET.get(key);
      if (!obj) return json({ error: 'not found' }, 404);
      if (isExpired(obj.customMetadata)) {
        await env.BUCKET.delete(key);
        return json({ error: 'expired' }, 410);
      }

      const name = obj.customMetadata?.n || key;
      const type = safeMime(obj.customMetadata?.t);

      const wantInline = url.searchParams.get('inline') === '1';
      const inline = wantInline && SAFE_INLINE_TYPES.has(type);

      const headers = {
        'Content-Type': inline
          ? type
          : (SAFE_INLINE_TYPES.has(type) ? type : 'application/octet-stream'),
        'Content-Length': String(obj.size),
        'Cache-Control': 'private, max-age=300',
        'X-Content-Type-Options': 'nosniff',
        'Cross-Origin-Resource-Policy': 'same-origin',
      };
      if (!inline) {
        headers['Content-Disposition'] =
          `attachment; filename*=UTF-8''${encodeURIComponent(name)}`;
      }

      return new Response(obj.body, { headers });
    }

    return json({ error: 'not found' }, 404);
  },

  /* ---------- 定时清理 ---------- */
  async scheduled(event, env, ctx) {
    const now = Date.now();

    const dead = [];
    for await (const o of listAll(env.BUCKET, {})) {
      // 对话下的消息按各自的过期机制处理（消息里的文件过期后仍会被 scheduled 单独清理）
      if (o.key.startsWith('conv/')) continue;

      if (o.key.startsWith('session/') || o.key.startsWith('ratelimit/')) {
        const exp = parseTs(o.customMetadata?.exp, 0);
        if (exp <= 0 || now > exp) dead.push(env.BUCKET.delete(o.key));
        continue;
      }

      // 剩下的就是文件对象
      if (isExpired(o.customMetadata)) {
        dead.push(env.BUCKET.delete(o.key));
      }
    }
    if (dead.length) await Promise.all(dead);
  },
};