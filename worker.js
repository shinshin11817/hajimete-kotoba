const SESSION_COOKIE = "hk_session";
const SESSION_DAYS = 30;
const PBKDF2_ITERATIONS = 100000;
 export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (!url.pathname.startsWith("/api/")) {
        const asset = await env.ASSETS.fetch(request);
        const headers = new Headers(asset.headers);
        // v0.3.1: allow this Web app to call its own /api/* endpoints.
        // Override any stale CSP previously applied by a _headers file.
        headers.set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("Referrer-Policy", "same-origin");
        headers.set("X-Frame-Options", "DENY");
        return new Response(asset.body, { status: asset.status, statusText: asset.statusText, headers });
      }
      if (request.method === "OPTIONS") return new Response(null, { status: 204 });
       const routes = {
        "GET /api/health": health,
        "POST /api/auth/register": register,
        "POST /api/auth/login": login,
        "POST /api/auth/logout": logout,
        "GET /api/me": me,
        "POST /api/families": createFamily,
        "GET /api/families": listFamilies,
        "POST /api/invitations": createInvitation,
        "POST /api/invitations/join": joinInvitation,
        "POST /api/children": createChild,
        "GET /api/children": listChildren,
        "POST /api/words": createWord,
        "GET /api/words": listWords,
        "DELETE /api/words": deleteWord
      };
      const handler = routes[`${request.method} ${url.pathname}`];
      if (!handler) return json({ error: "not_found" }, 404);
      return await handler(request, env, url);
    } catch (error) {
      console.error(error);
      return json({ error: "server_error", message: "処理に失敗しました" }, 500);
    }
  }
};
 async function health(_req, env) {
  const result = await env.DB.prepare("SELECT 1 AS ok").first();
  return json({ status: "ok", database: result?.ok === 1, version: "0.3.2" });
}
 async function register(req, env) {
  const b = await body(req);
  const email = normalizeEmail(b.email);
  const name = clean(b.displayName, 40);
  const password = String(b.password || "");
  if (!validEmail(email) || name.length < 1 || password.length < 12) {
    return json({ error: "invalid_input", message: "メール、表示名、12文字以上のパスワードを入力してください" }, 400);
  }
  const exists = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
  if (exists) return json({ error: "email_exists" }, 409);
  const id = crypto.randomUUID(), now = iso();
  const salt = randomToken(16);
  const hash = await passwordHash(password, salt, PBKDF2_ITERATIONS);
  await env.DB.prepare("INSERT INTO users(id,email,display_name,password_salt,password_hash,password_iterations,created_at) VALUES(?,?,?,?,?,?,?)")
    .bind(id, email, name, salt, hash, PBKDF2_ITERATIONS, now).run();
  return issueSession(env, id, { id, email, displayName: name }, 201);
}
 async function login(req, env) {
  const b = await body(req), email = normalizeEmail(b.email), password = String(b.password || "");
  const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
  if (!user) return json({ error: "invalid_credentials" }, 401);
  const actual = await passwordHash(password, user.password_salt, user.password_iterations);
  if (!timingSafe(actual, user.password_hash)) return json({ error: "invalid_credentials" }, 401);
  return issueSession(env, user.id, { id: user.id, email: user.email, displayName: user.display_name }, 200);
}
 async function logout(req, env) {
  const token = cookie(req, SESSION_COOKIE);
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE id_hash = ?").bind(await sha256(token)).run();
  return json({ ok: true }, 200, clearCookie());
}
 async function me(req, env) {
  const user = await requireUser(req, env);
  if (user.response) return user.response;
  return json({ user: user.value });
}
 async function createFamily(req, env) {
  const u = await requireUser(req, env); if (u.response) return u.response;
  const b = await body(req), name = clean(b.name, 50); if (!name) return json({ error: "invalid_name" }, 400);
  const id = crypto.randomUUID(), now = iso();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO families(id,name,owner_user_id,created_at) VALUES(?,?,?,?)").bind(id, name, u.value.id, now),
    env.DB.prepare("INSERT INTO family_members(family_id,user_id,role,joined_at) VALUES(?,?,?,?)").bind(id, u.value.id, "owner", now)
  ]);
  return json({ family: { id, name, role: "owner" } }, 201);
}
 async function listFamilies(req, env) {
  const u = await requireUser(req, env); if (u.response) return u.response;
  const r = await env.DB.prepare("SELECT f.id,f.name,m.role,f.created_at FROM families f JOIN family_members m ON m.family_id=f.id WHERE m.user_id=? ORDER BY f.created_at")
    .bind(u.value.id).all();
  return json({ families: r.results });
}
 async function createInvitation(req, env) {
  const u = await requireUser(req, env); if (u.response) return u.response;
  const b = await body(req), familyId = String(b.familyId || ""), role = b.role === "viewer" ? "viewer" : "member";
  const access = await membership(env, u.value.id, familyId);
  if (!access || access.role !== "owner") return json({ error: "forbidden" }, 403);
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const id = crypto.randomUUID(), now = new Date(), expiry = new Date(now.getTime() + 24 * 3600 * 1000);
  await env.DB.prepare("INSERT INTO invitations(id,family_id,code_hash,role,expires_at,created_by,created_at) VALUES(?,?,?,?,?,?,?)")
    .bind(id, familyId, await sha256(code), role, expiry.toISOString(), u.value.id, now.toISOString()).run();
  return json({ invitation: { id, code, expiresAt: expiry.toISOString(), role } }, 201);
}
 async function joinInvitation(req, env) {
  const u = await requireUser(req, env); if (u.response) return u.response;
  const b = await body(req), code = String(b.code || "").replace(/\D/g, "");
  if (code.length !== 6) return json({ error: "invalid_code" }, 400);
  const inv = await env.DB.prepare("SELECT * FROM invitations WHERE code_hash=? AND used_at IS NULL AND expires_at>?")
    .bind(await sha256(code), iso()).first();
  if (!inv) return json({ error: "invalid_or_expired_code" }, 404);
  const now = iso();
  await env.DB.batch([
    env.DB.prepare("INSERT OR IGNORE INTO family_members(family_id,user_id,role,joined_at) VALUES(?,?,?,?)").bind(inv.family_id, u.value.id, inv.role, now),
    env.DB.prepare("UPDATE invitations SET used_at=?,used_by=? WHERE id=? AND used_at IS NULL").bind(now, u.value.id, inv.id)
  ]);
  return json({ familyId: inv.family_id, role: inv.role });
}
 async function createChild(req, env) {
  const u = await requireUser(req, env); if (u.response) return u.response;
  const b = await body(req), familyId = String(b.familyId || ""), name = clean(b.name, 30), birthday = dateOnly(b.birthday);
  const access = await membership(env, u.value.id, familyId);
  if (!access || access.role === "viewer") return json({ error: "forbidden" }, 403);
  if (!name || !birthday) return json({ error: "invalid_input" }, 400);
  const id = crypto.randomUUID(), now = iso();
  await env.DB.prepare("INSERT INTO children(id,family_id,name,birthday,created_by,created_at) VALUES(?,?,?,?,?,?)")
    .bind(id, familyId, name, birthday, u.value.id, now).run();
  return json({ child: { id, familyId, name, birthday } }, 201);
}
 async function listChildren(req, env, url) {
  const u = await requireUser(req, env); if (u.response) return u.response;
  const familyId = url.searchParams.get("familyId") || "";
  if (!(await membership(env, u.value.id, familyId))) return json({ error: "forbidden" }, 403);
  const r = await env.DB.prepare("SELECT id,family_id,name,birthday,created_at FROM children WHERE family_id=? ORDER BY created_at")
    .bind(familyId).all();
  return json({ children: r.results });
}
 async function createWord(req, env) {
  const u = await requireUser(req, env); if (u.response) return u.response;
  const b = await body(req), familyId = String(b.familyId || ""), childId = String(b.childId || "");
  const access = await membership(env, u.value.id, familyId);
  if (!access || access.role === "viewer") return json({ error: "forbidden" }, 403);
  const child = await env.DB.prepare("SELECT id FROM children WHERE id=? AND family_id=?").bind(childId, familyId).first();
  const word = clean(b.word, 80), spoken = dateOnly(b.spokenAt);
  if (!child || !word || !spoken) return json({ error: "invalid_input" }, 400);
  const id = crypto.randomUUID(), now = iso();
  await env.DB.prepare(`INSERT INTO words(id,family_id,child_id,word,spoken_at,toward,category,memo,is_first,is_favorite,media_type,created_by,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .bind(id, familyId, childId, word, spoken, clean(b.toward,30)||null, clean(b.category,30)||null, clean(b.memo,500)||null,
      b.isFirst ? 1 : 0, b.isFavorite ? 1 : 0, "text", u.value.id, now, now).run();
  return json({ word: { id, familyId, childId, word, spokenAt: spoken } }, 201);
}
 async function listWords(req, env, url) {
  const u = await requireUser(req, env); if (u.response) return u.response;
  const familyId = url.searchParams.get("familyId") || "";
  if (!(await membership(env, u.value.id, familyId))) return json({ error: "forbidden" }, 403);
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit")) || 50, 1), 100);
  const r = await env.DB.prepare(`SELECT id,family_id,child_id,word,spoken_at,toward,category,memo,is_first,is_favorite,media_type,media_key,media_mime,media_size,created_by,created_at,updated_at
    FROM words WHERE family_id=? ORDER BY spoken_at DESC,created_at DESC LIMIT ?`).bind(familyId, limit).all();
  return json({ words: r.results });
}
 async function deleteWord(req, env, url) {
  const u = await requireUser(req, env); if (u.response) return u.response;
  const id = url.searchParams.get("id") || "";
  const w = await env.DB.prepare("SELECT * FROM words WHERE id=?").bind(id).first();
  if (!w) return json({ error: "not_found" }, 404);
  const access = await membership(env, u.value.id, w.family_id);
  if (!access || (access.role !== "owner" && w.created_by !== u.value.id)) return json({ error: "forbidden" }, 403);
  await env.DB.prepare("DELETE FROM words WHERE id=?").bind(id).run();
  return json({ ok: true });
}
 async function requireUser(req, env) {
  const token = cookie(req, SESSION_COOKIE);
  if (!token) return { response: json({ error: "unauthorized" }, 401) };
  const row = await env.DB.prepare(`SELECT u.id,u.email,u.display_name FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.id_hash=? AND s.expires_at>?`).bind(await sha256(token), iso()).first();
  if (!row) return { response: json({ error: "unauthorized" }, 401, clearCookie()) };
  return { value: { id: row.id, email: row.email, displayName: row.display_name } };
}
 async function membership(env, userId, familyId) {
  if (!familyId) return null;
  return env.DB.prepare("SELECT role FROM family_members WHERE user_id=? AND family_id=?").bind(userId, familyId).first();
}
 async function issueSession(env, userId, user, status) {
  const token = randomToken(32), now = new Date(), expires = new Date(now.getTime() + SESSION_DAYS * 86400000);
  await env.DB.prepare("INSERT INTO sessions(id_hash,user_id,expires_at,created_at,last_seen_at) VALUES(?,?,?,?,?)")
    .bind(await sha256(token), userId, expires.toISOString(), now.toISOString(), now.toISOString()).run();
  return json({ user }, status, `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`);
}
 async function body(req) {
  const type = req.headers.get("content-type") || "";
  if (!type.includes("application/json")) throw new Error("JSON required");
  return req.json();
}
function json(data, status=200, setCookie) {
  const h = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" };
  if (setCookie) h["set-cookie"] = setCookie;
  return new Response(JSON.stringify(data, null, 2), { status, headers: h });
}
function clearCookie() { return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`; }
function cookie(req, name) {
  const m = (req.headers.get("cookie") || "").match(new RegExp(`(?:^|; )${name}=([^;]*)`)); return m ? m[1] : "";
}
function clean(v, max) { return String(v || "").trim().replace(/[\u0000-\u001f\u007f]/g, "").slice(0, max); }
function normalizeEmail(v) { return String(v || "").trim().toLowerCase(); }
function validEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 254; }
function dateOnly(v) { const s = String(v || ""); return /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : ""; }
function iso() { return new Date().toISOString(); }
function randomToken(bytes) {
  const a = new Uint8Array(bytes); crypto.getRandomValues(a); return base64url(a);
}
function base64url(bytes) { return btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,""); }
async function sha256(v) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)); return base64url(new Uint8Array(d));
}
async function passwordHash(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name:"PBKDF2", hash:"SHA-256", salt:new TextEncoder().encode(salt), iterations }, key, 256);
  return base64url(new Uint8Array(bits));
}
function timingSafe(a, b) {
  if (a.length !== b.length) return false; let x = 0; for (let i=0;i<a.length;i++) x |= a.charCodeAt(i)^b.charCodeAt(i); return x===0;
}
