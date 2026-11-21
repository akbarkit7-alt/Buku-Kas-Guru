const H = { 'content-type': 'application/json', 'cache-control': 'no-store' };
const out = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: H });
const hash = async s => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('kas:' + s)))].map(x => x.toString(16).padStart(2, '0')).join('');

async function ok(req, env) {
  const pw = (req.headers.get('x-admin') || '').trim();
  if (!pw) return false;
  const h = await env.KAS.get('pwh');
  return h ? (await hash(pw)) === h : !!env.ADMIN_PASSWORD && pw === String(env.ADMIN_PASSWORD).trim();
}

async function guard(req, env) {
  if (!env.ADMIN_PASSWORD && !(await env.KAS.get('pwh'))) return out({ error: 'ADMIN_PASSWORD belum diatur' }, 500);
  const k = 'fail:' + (req.headers.get('cf-connecting-ip') || 'x'), n = +((await env.KAS.get(k)) || 0);
  if (n >= 5) return out({ error: 'Terlalu banyak percobaan. Coba lagi 15 menit lagi.' }, 429);
  if (await ok(req, env)) return null;
  await env.KAS.put(k, String(n + 1), { expirationTtl: 900 });
  return out({ error: 'Password salah' }, 401);
}

// INI BAGIAN YANG TADI SALAH TEMPAT
export async function onRequestGet({ request, env }) {
  const raw = await env.KAS.get('state');
  if (!raw) return out({ periods: [], log: [] }); // <--- INI YANG BENAR
  
  if (await ok(request, env)) return new Response(raw, { headers: H });
  const d = JSON.parse(raw);
  d.periods.forEach(p => delete p.mem);
  delete d.log;
  return out(d);
}

export async function onRequestPost({ request, env }) {
  const g = await guard(request, env);
  if (g) return g;
  let b = {};
  try { b = await request.json(); } catch {}
  if (b.new) {
    if (String(b.new).length < 6) return out({ error: 'Password minimal 6 karakter' }, 400);
    await env.KAS.put('pwh', await hash(String(b.new)));
  }
  return out({ ok: true });
}

export async function onRequestPut({ request, env }) {
  const g = await guard(request, env);
  if (g) return g;
  const body = await request.text();
  if (body.length > 5e6) return out({ error: 'Data terlalu besar' }, 413);
  let d;
  try { d = JSON.parse(body); } catch { return out({ error: 'Data rusak' }, 400); }
  if (!d || !Array.isArray(d.periods) || !d.periods.length) return out({ error: 'Format tidak valid' }, 400);
  await env.KAS.put('state', body);
  await env.KAS.put('bak:' + new Date().toISOString().slice(0, 10), body, { expirationTtl: 60 * 86400 });
  return out({ ok: true });
}
