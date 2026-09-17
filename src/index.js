
const SESSION_TTL = 60 * 60 * 24 * 7;
const SESSION_TTL_MS = SESSION_TTL * 1000;

const LOGIN_WINDOW_MS = 60_000;
const LOGIN_MAX_ATTEMPTS = 5;

const JSON_MAX_BYTES = 1_000_000;
const MERGE_WINDOW = 5 * 60_000;

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

    /* ---------- 文本 ---------- */
    if (path === '/api/text') {
      if (request.method === 'GET') {
        const obj = await env.BUCKET.get('text/latest');
        const value = obj ? await obj.text() : '';
        return json({ value });
      }

      if (request.method === 'POST') {
        let body;
        try { body = await safeJsonBody(request); }
        catch (e) {
          return e instanceof Response ? e : json({ error: 'bad request' }, 400);
        }

        const value = body.value;
        const saveHistory = body.saveHistory !== false;
        const force = body.force === true;

        if (typeof value !== 'string' || value.length > 200_000) {
          return json({ error: 'invalid' }, 400);
        }

        if (!value) {
          await env.BUCKET.delete('text/latest');
          return json({ ok: true });
        }

        await env.BUCKET.put('text/latest', value);

        if (!saveHistory) return json({ ok: true });

        const ts = Date.now();

        if (force) {
          const id = `${ts}-${crypto.randomUUID().slice(0, 8)}`;
          await env.BUCKET.put(`text/history/${id}`, value, {
            customMetadata: { m: '1' },
          });
          return json({ ok: true, id, ts, manual: true });
        }

        const hist = await env.BUCKET.list({
          prefix: 'text/history/',
          limit: 1000,
        });

        let latestKey = null;
        let latestTs = 0;
        let latestManual = false;

        for (const o of hist.objects) {
          if (!latestKey || o.key > latestKey) {
            latestKey = o.key;
            const idPart = o.key.slice('text/history/'.length);
            latestTs = parseTs(idPart.split('-')[0], 0);
            latestManual = o.customMetadata?.m === '1';
          }
        }

        if (latestKey && !latestManual && ts - latestTs < MERGE_WINDOW) {
          await env.BUCKET.put(latestKey, value, {
            customMetadata: { m: '0' },
          });
          return json({
            ok: true,
            id: latestKey.slice('text/history/'.length),
            ts: latestTs,
            merged: true,
          });
        }

        const id = `${ts}-${crypto.randomUUID().slice(0, 8)}`;
        await env.BUCKET.put(`text/history/${id}`, value, {
          customMetadata: { m: '0' },
        });
        return json({ ok: true, id, ts });
      }
    }

    if (path === '/api/text/history' && request.method === 'GET') {
      const limit = Math.min(
        Math.max(parseTs(url.searchParams.get('limit'), 20), 1),
        100
      );

      const all = [];
      for await (const o of listAll(env.BUCKET, { prefix: 'text/history/' })) {
        all.push(o);
      }
      all.sort((a, b) => b.key.localeCompare(a.key));

      const top = all.slice(0, limit);
      const versions = await Promise.all(
        top.map(async (o) => {
          const obj = await env.BUCKET.get(o.key);
          const id = o.key.slice('text/history/'.length);
          return {
            id,
            ts: parseTs(id.split('-')[0], 0),
            value: obj ? await obj.text() : '',
            manual: obj?.customMetadata?.m === '1',
          };
        })
      );
      return json({ versions });
    }

    if (path === '/api/text/restore' && request.method === 'POST') {
      let body;
      try { body = await safeJsonBody(request); }
      catch (e) {
        return e instanceof Response ? e : json({ error: 'bad request' }, 400);
      }
      const { id } = body;
      if (!id || typeof id !== 'string' || id.length > 100 || id.includes('/')) {
        return json({ error: 'invalid id' }, 400);
      }

      const obj = await env.BUCKET.get('text/history/' + id);
      if (!obj) return json({ error: 'not found' }, 404);

      const value = await obj.text();
      await env.BUCKET.put('text/latest', value);

      const ts = Date.now();
      const newId = `${ts}-${crypto.randomUUID().slice(0, 8)}`;
      await env.BUCKET.put(`text/history/${newId}`, value, {
        customMetadata: { m: '1' },
      });

      return json({ ok: true, value, id: newId, ts });
    }

    if (path.startsWith('/api/text/history/') && request.method === 'DELETE') {
      const id = safeDecode(path.slice('/api/text/history/'.length));
      if (!id || id.length > 100 || id.includes('/')) {
        return json({ error: 'bad id' }, 400);
      }
      await env.BUCKET.delete('text/history/' + id);
      return json({ ok: true });
    }

    /* ---------- 文件 ---------- */
    if (path === '/api/files' && request.method === 'GET') {
      const files = [];
      const gc = [];

      for await (const o of listAll(env.BUCKET, {})) {
        if (o.key.startsWith('session/') ||
            o.key.startsWith('text/') ||
            o.key.startsWith('ratelimit/')) continue;

        if (isExpired(o.customMetadata)) {
          gc.push(env.BUCKET.delete(o.key));
          continue;
        }

        files.push({
          key: o.key,
          size: o.size,
          uploaded: o.uploaded,
          name: o.customMetadata?.n || o.key,
          type: safeMime(o.customMetadata?.t),
          exp: parseTs(o.customMetadata?.e, 0),
        });
      }
      if (gc.length) ctx.waitUntil(Promise.all(gc));

      files.sort((a, b) => b.uploaded - a.uploaded);
      return json({ files });
    }

    if (path === '/api/files' && request.method === 'POST') {
      if (!request.body) return json({ error: 'no body' }, 400);

      const key = crypto.randomUUID();
      const rawName = request.headers.get('X-File-Name') || '';
      const name = safeDecode(rawName).slice(0, 255).replace(/[\r\n\t]/g, ' ');
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

    if (path.startsWith('/api/files/')) {
      const key = safeDecode(path.slice('/api/files/'.length));
      if (!key || key.length > 100 || key.includes('/')) {
        return json({ error: 'bad key' }, 400);
      }

      if (request.method === 'GET') {
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

      if (request.method === 'PATCH') {
        let body;
        try { body = await safeJsonBody(request); }
        catch (e) {
          return e instanceof Response ? e : json({ error: 'bad request' }, 400);
        }
        const rawName = body.name;
        if (typeof rawName !== 'string' || !rawName.trim() || rawName.length > 255) {
          return json({ error: 'invalid name' }, 400);
        }
        const name = rawName.trim().replace(/[\r\n\t]/g, ' ');

        const obj = await env.BUCKET.get(key);
        if (!obj) return json({ error: 'not found' }, 404);
        if (isExpired(obj.customMetadata)) {
          await env.BUCKET.delete(key);
          return json({ error: 'expired' }, 410);
        }

        const meta = { ...(obj.customMetadata || {}), n: name };
        await env.BUCKET.put(key, obj.body, {
          customMetadata: meta,
          httpMetadata: obj.httpMetadata,
        });

        return json({ ok: true, name });
      }

      if (request.method === 'DELETE') {
        await env.BUCKET.delete(key);
        return json({ ok: true });
      }
    }

    return json({ error: 'not found' }, 404);
  },

  async scheduled(event, env, ctx) {
    const now = Date.now();
    const DAY = 86400_000;

    const dead = [];
    for await (const o of listAll(env.BUCKET, {})) {
      if (o.key.startsWith('text/')) continue;

      if (o.key.startsWith('session/') || o.key.startsWith('ratelimit/')) {
        const exp = parseTs(o.customMetadata?.exp, 0);
        if (exp <= 0 || now > exp) dead.push(env.BUCKET.delete(o.key));
        continue;
      }

      if (isExpired(o.customMetadata)) {
        dead.push(env.BUCKET.delete(o.key));
      }
    }
    if (dead.length) await Promise.all(dead);

    const KEEP = 50;
    const cutoff = now - 30 * DAY;
    const all = [];
    for await (const o of listAll(env.BUCKET, { prefix: 'text/history/' })) {
      all.push(o);
    }
    all.sort((a, b) => b.key.localeCompare(a.key));

    const toDelete = [];
    for (let i = 0; i < all.length; i++) {
      const ts = parseTs(all[i].key.slice('text/history/'.length).split('-')[0], 0);
      if (i >= KEEP || (ts > 0 && ts < cutoff)) {
        toDelete.push(all[i].key);
      }
    }
    if (toDelete.length) {
      await Promise.all(toDelete.map((k) => env.BUCKET.delete(k)));
    }
  },
};
