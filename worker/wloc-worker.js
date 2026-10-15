/**
 * WLOC Location Spoofer - Cloudflare Worker (multi-tenant SaaS edition)
 *
 * The picker page + /api/parse are gated behind per-user tokens stored in KV.
 * Coordinates themselves still live on each user's device ($persistentStore
 * via the proxy module's MITM on gs-loc.apple.com) - the Worker stores no
 * location data, only access tokens.
 *
 * Bindings required:
 *   - KV namespace bound as WLOC_TOKENS
 *   - Secret ADMIN_SECRET (Bearer token for /admin API)
 *
 * Token model in KV: "token:<tok>" -> JSON {
 *   note, createdAt, expiresAt (0 = never), revoked, lastUsedAt }
 *
 * Routes:
 *   GET /?token=xxx            picker page (token required)
 *   GET /api/parse?token=&url= link parser (token required)
 *   GET /admin                  admin login page
 *   GET /admin/api/tokens       list tokens (Bearer ADMIN_SECRET)
 *   POST /admin/api/tokens      create token {note, days} (Bearer)
 *   DELETE /admin/api/tokens/<tok>  revoke token (Bearer)
 *
 * Deploy: Cloudflare Workers (KV binding + secret needed)
 */

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		if (request.method === "OPTIONS") {
			return new Response(null, { headers: { "Access-Control-Allow-Origin": "*" } });
		}
		// Admin console + API (protected by ADMIN_SECRET)
		if (url.pathname === "/admin" || url.pathname.startsWith("/admin/")) {
			return handleAdmin(request, url, env);
		}
		// Public sales / landing page (no token needed)
		if (url.pathname === "/buy") {
			return new Response(buyPageHtml(), {
				headers: { "Content-Type": "text/html;charset=utf-8", "Cache-Control": "no-cache" },
			});
		}
		// Token gate for the picker page and the parse API
		const token = (url.searchParams.get("token") || "").trim();
		const check = await checkToken(env, token);
		if (!check.ok) {
			if (url.pathname === "/api/parse") {
				return jsonResp({ error: check.error }, 403, {
					"Content-Type": "application/json;charset=utf-8",
					"Access-Control-Allow-Origin": "*",
				});
			}
			return tokenDeniedPage(check.error);
		}
		if (url.pathname === "/api/parse") {
			return handleApiParse(url);
		}
		return servePage(url);
	},
};

/* ---------------- Token gating (KV-backed) ---------------- */

function jsonHeaders() {
	return { "Content-Type": "application/json;charset=utf-8", "Access-Control-Allow-Origin": "*" };
}

async function checkToken(env, token) {
	if (!token) return { ok: false, error: "missing token" };
	if (!env.WLOC_TOKENS) return { ok: false, error: "server misconfigured (no KV)" };
	let raw = null;
	try {
		raw = await env.WLOC_TOKENS.get("token:" + token);
	} catch (e) {
		return { ok: false, error: "token store unavailable" };
	}
	if (!raw) return { ok: false, error: "invalid token" };
	let info;
	try {
		info = JSON.parse(raw);
	} catch (e) {
		return { ok: false, error: "invalid token" };
	}
	if (info.revoked) return { ok: false, error: "token revoked" };
	if (info.expiresAt && Date.now() > info.expiresAt) return { ok: false, error: "token expired" };
	// Refresh lastUsedAt at most once per hour (keeps KV writes tiny)
	if (!info.lastUsedAt || Date.now() - info.lastUsedAt > 3600000) {
		info.lastUsedAt = Date.now();
		try {
			await env.WLOC_TOKENS.put("token:" + token, JSON.stringify(info));
		} catch (e) { /* non-fatal */ }
	}
	return { ok: true, info: info };
}

function tokenDeniedPage(reason) {
	const msg = {
		"missing token": "缺少访问 token",
		"invalid token": "token 无效",
		"token revoked": "token 已被停用",
		"token expired": "token 已过期，请续费",
		"server misconfigured (no KV)": "服务端未配置",
		"token store unavailable": "服务端暂时不可用",
	}[reason] || reason;
	const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WLOC - 需要授权</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;background:#f2f2f7;display:flex;align-items:center;justify-content:center;min-height:90vh;margin:0}
.card{background:#fff;border-radius:16px;padding:32px 28px;max-width:340px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.08)}
h1{font-size:20px;margin:0 0 8px}.p{color:#8e8e93;font-size:14px;line-height:1.6}</style>
</head><body><div class="card"><h1>🔒 需要授权</h1>
<p class="p">${msg}。<br>请使用你的专属链接访问，或联系客服开通。</p></div></body></html>`;
	return new Response(html, { status: 403, headers: { "Content-Type": "text/html;charset=utf-8" } });
}

/* ---------------- Admin console ----------------
 * GET /admin -> login page; all /admin/api/* need Authorization: Bearer <ADMIN_SECRET>
 */

async function handleAdmin(request, url, env) {
	const secret = (env.ADMIN_SECRET || "").trim();
	const authed = secret && (request.headers.get("Authorization") || "").trim() === "Bearer " + secret;

	if (url.pathname === "/admin" && request.method === "GET") {
		return new Response(adminPageHtml(), { headers: { "Content-Type": "text/html;charset=utf-8" } });
	}
	if (!authed) {
		return jsonResp({ error: "unauthorized" }, 401, jsonHeaders());
	}
	if (!env.WLOC_TOKENS) {
		return jsonResp({ error: "server misconfigured (no KV)" }, 500, jsonHeaders());
	}

	// GET /admin/api/tokens -> list
	if (url.pathname === "/admin/api/tokens" && request.method === "GET") {
		const out = [];
		let cursor = undefined;
		do {
			const page = await env.WLOC_TOKENS.list({ prefix: "token:", cursor: cursor });
			for (const k of page.keys) {
				const raw = await env.WLOC_TOKENS.get(k.name);
				let info = {};
				try { info = JSON.parse(raw || "{}"); } catch (e) {}
				out.push({
					token: k.name.slice("token:".length),
					note: info.note || "",
					createdAt: info.createdAt || 0,
					expiresAt: info.expiresAt || 0,
					revoked: !!info.revoked,
					lastUsedAt: info.lastUsedAt || 0,
				});
			}
			cursor = page.list_complete ? undefined : page.cursor;
		} while (cursor);
		out.sort((a, b) => b.createdAt - a.createdAt);
		return jsonResp({ tokens: out }, 200, jsonHeaders());
	}

	// POST /admin/api/tokens {note, days} -> create
	if (url.pathname === "/admin/api/tokens" && request.method === "POST") {
		let body = {};
		try { body = await request.json(); } catch (e) {}
		const note = String(body.note || "").slice(0, 80);
		const days = Math.max(0, parseInt(body.days, 10) || 0);
		const tok = "wloc_" + crypto.randomUUID().replace(/-/g, "");
		const now = Date.now();
		const info = {
			note: note,
			createdAt: now,
			expiresAt: days > 0 ? now + days * 86400000 : 0,
			revoked: false,
			lastUsedAt: 0,
		};
		await env.WLOC_TOKENS.put("token:" + tok, JSON.stringify(info));
		return jsonResp({ token: tok, info: info }, 200, jsonHeaders());
	}

	// DELETE /admin/api/tokens/<tok> -> revoke
	const m = url.pathname.match(/^\/admin\/api\/tokens\/([A-Za-z0-9_]+)$/);
	if (m && request.method === "DELETE") {
		const key = "token:" + m[1];
		const raw = await env.WLOC_TOKENS.get(key);
		if (!raw) return jsonResp({ error: "not found" }, 404, jsonHeaders());
		let info = {};
		try { info = JSON.parse(raw); } catch (e) {}
		info.revoked = true;
		await env.WLOC_TOKENS.put(key, JSON.stringify(info));
		return jsonResp({ ok: true }, 200, jsonHeaders());
	}

	return jsonResp({ error: "not found" }, 404, jsonHeaders());
}

function adminPageHtml() {
	return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WLOC 管理后台</title>
<style>
body{font-family:-apple-system,system-ui,sans-serif;background:#f2f2f7;margin:0;padding:16px;color:#1c1c1e}
.wrap{max-width:720px;margin:0 auto}
.card{background:#fff;border-radius:14px;padding:18px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.06)}
h2{font-size:17px;margin:0 0 12px}
input,button{font-size:14px;padding:10px 12px;border-radius:9px;border:1px solid #d1d1d6;outline:none}
input{width:100%;box-sizing:border-box;margin-bottom:8px}
input:focus{border-color:#007aff}
.btn{background:#007aff;color:#fff;border:none;cursor:pointer;font-weight:600}
.btn:active{opacity:.85}
.btn-danger{background:#ff3b30;color:#fff;border:none;cursor:pointer;padding:6px 12px;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid #eee;vertical-align:top}
th{color:#8e8e93;font-weight:600;font-size:11px}
.mono{font-family:ui-monospace,monospace;word-break:break-all}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600}
.ok{background:#d2f5d2;color:#1a7a1a}.bad{background:#ffd9d9;color:#c00}.warn{background:#ffe9c2;color:#a05a00}
.row{display:flex;gap:8px}.row input{flex:1;margin-bottom:0}
.hint{font-size:12px;color:#8e8e93;margin-top:8px;line-height:1.6}
#login{max-width:380px;margin:60px auto}
.hidden{display:none}
</style></head><body><div class="wrap">
<div class="card" id="login">
  <h2>🔑 WLOC 管理后台</h2>
  <input type="password" id="pw" placeholder="输入管理密钥">
  <button class="btn" style="width:100%" onclick="doLogin()">进入</button>
  <div class="hint">管理密钥只保存在本浏览器会话中，不会发送到除本服务外的任何地方。</div>
</div>
<div id="main" class="hidden">
  <div class="card">
    <h2>➕ 开通新用户</h2>
    <div class="row">
      <input id="note" placeholder="备注（如：微信 xxx）" maxlength="80">
      <input id="days" type="number" placeholder="有效天数（0=永久）" style="max-width:150px">
      <button class="btn" onclick="createToken()">生成</button>
    </div>
    <div class="hint" id="newTok"></div>
  </div>
  <div class="card">
    <h2>👥 用户 token <button class="btn" style="padding:6px 14px;font-size:12px" onclick="loadTokens()">刷新</button></h2>
    <div id="list">加载中…</div>
  </div>
</div>
</div>
<script>
let SECRET = sessionStorage.getItem('wloc_admin') || '';
if (SECRET) { document.getElementById('login').classList.add('hidden'); document.getElementById('main').classList.remove('hidden'); loadTokens(); }
async function api(path, method, body) {
  const r = await fetch(path, { method: method || 'GET',
    headers: { 'Authorization': 'Bearer ' + SECRET, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined });
  if (r.status === 401) { sessionStorage.removeItem('wloc_admin'); location.reload(); throw new Error('unauthorized'); }
  return r.json();
}
async function doLogin() {
  SECRET = document.getElementById('pw').value.trim();
  if (!SECRET) return;
  try { await api('/admin/api/tokens'); sessionStorage.setItem('wloc_admin', SECRET);
    document.getElementById('login').classList.add('hidden'); document.getElementById('main').classList.remove('hidden'); loadTokens();
  } catch(e) { alert('密钥错误'); }
}
function fmt(ts) { return ts ? new Date(ts).toLocaleString('zh-CN', {hour12:false}) : '-'; }
async function loadTokens() {
  const el = document.getElementById('list');
  try {
    const d = await api('/admin/api/tokens');
    if (!d.tokens.length) { el.innerHTML = '<div class="hint">暂无用户</div>'; return; }
    el.innerHTML = '<table><tr><th>Token</th><th>备注</th><th>开通</th><th>到期</th><th>最后使用</th><th>状态</th><th></th></tr>' +
      d.tokens.map(t2 => '<tr><td class="mono">' + t2.token.slice(0,12) + '…</td><td>' + esc(t2.note) + '</td><td>' + fmt(t2.createdAt) + '</td><td>' + (t2.expiresAt ? fmt(t2.expiresAt) : '永久') + '</td><td>' + fmt(t2.lastUsedAt) + '</td><td>' +
      (t2.revoked ? '<span class="badge bad">已停用</span>' : (t2.expiresAt && Date.now() > t2.expiresAt ? '<span class="badge warn">已过期</span>' : '<span class="badge ok">正常</span>')) + '</td><td>' +
      (t2.revoked ? '' : '<button class="btn-danger" onclick="revoke(\\'' + t2.token + '\\')">停用</button>') + '</td></tr>').join('') + '</table>';
  } catch(e) { el.innerHTML = '<div class="hint">加载失败</div>'; }
}
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
async function createToken() {
  const note = document.getElementById('note').value.trim();
  const days = parseInt(document.getElementById('days').value, 10) || 0;
  const d = await api('/admin/api/tokens', 'POST', { note: note, days: days });
  const link = location.origin + '/?token=' + d.token;
  document.getElementById('newTok').innerHTML = '✅ 已生成，发给用户这个专属链接：<br><span class="mono">' + link + '</span>';
  document.getElementById('note').value = '';
  loadTokens();
}
async function revoke(tok) {
  if (!confirm('确定停用这个 token？用户将立即无法使用。')) return;
  await api('/admin/api/tokens/' + tok, 'DELETE');
  loadTokens();
}
</script></body></html>`;
}

/* ---------------- /buy: 公开落地页 ---------------- */

function buyPageHtml() {
	return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WLOC · iOS 虚拟定位服务</title>
<style>
body{font-family:-apple-system,system-ui,sans-serif;background:#f2f2f7;margin:0;color:#1c1c1e}
.wrap{max-width:560px;margin:0 auto;padding:20px 16px 60px}
.hero{background:linear-gradient(135deg,#007aff,#5856d6);color:#fff;border-radius:20px;padding:32px 24px;text-align:center;margin-bottom:14px}
.hero h1{margin:0 0 8px;font-size:24px}
.hero p{margin:0;opacity:.9;font-size:14px;line-height:1.7}
.card{background:#fff;border-radius:16px;padding:20px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.card h2{font-size:17px;margin:0 0 12px}
.price{display:flex;gap:10px;margin-bottom:6px}
.plan{flex:1;border:2px solid #e5e5ea;border-radius:12px;padding:14px 10px;text-align:center}
.plan.hot{border-color:#007aff;background:#f0f7ff}
.plan .p1{font-size:13px;color:#8e8e93}
.plan .p2{font-size:22px;font-weight:700;margin:4px 0}
.plan .p3{font-size:12px;color:#8e8e93}
ol,ul{margin:0;padding-left:20px;font-size:14px;line-height:2}
.faq{font-size:13px;color:#555;line-height:1.8}
.faq b{color:#1c1c1e}
.cta{display:block;background:#007aff;color:#fff;text-align:center;padding:15px;border-radius:14px;font-size:16px;font-weight:700;text-decoration:none;margin-top:14px}
.note{font-size:12px;color:#8e8e93;text-align:center;margin-top:10px;line-height:1.7}
.badge{display:inline-block;background:#ff9500;color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;margin-bottom:8px}
</style></head><body><div class="wrap">
<div class="hero">
  <h1>📍 WLOC 虚拟定位</h1>
  <p>为 iPhone 打造的虚拟定位服务<br>无需越狱 · 改系统级定位 · 全部 App 生效</p>
</div>
<div class="card">
  <h2>✨ 能做什么</h2>
  <ul>
    <li>在地图上点选任意位置，一键修改 iPhone 定位</li>
    <li>粘贴 Apple / 高德 / Google 地图分享链接直接定位</li>
    <li>收藏常用地点，随时切换</li>
    <li>修改的是系统级定位，微信、相机、打卡 App 全部生效</li>
  </ul>
</div>
<div class="card">
  <span class="badge">限时优惠</span>
  <h2>💰 价格</h2>
  <div class="price">
    <div class="plan"><div class="p1">月付</div><div class="p2">¥29</div><div class="p3">灵活体验</div></div>
    <div class="plan hot"><div class="p1">年付</div><div class="p2">¥199</div><div class="p3">平均 ¥16.6/月</div></div>
  </div>
  <div class="note">以上为建议价，实际以下单时客服报价为准</div>
</div>
<div class="card">
  <h2>🛒 怎么开通</h2>
  <ol>
    <li>添加客服微信（下单时获取），备注 <b>WLOC</b></li>
    <li>付款后客服 10 分钟内发你 <b>专属链接</b></li>
    <li>按附赠的傻瓜教程配置（约 10 分钟，一次搞定）</li>
  </ol>
  <a class="cta" href="#" onclick="alert('请联系客服微信下单');return false;">联系客服开通</a>
  <div class="note">你需要一台 iPhone + 购买 Stash（约 ¥20，一次性）</div>
</div>
<div class="card">
  <h2>❓ 常见问题</h2>
  <div class="faq">
    <b>Q: 需要越狱吗？</b><br>A: 不需要。利用代理 + 描述文件实现，系统保持原装。<br><br>
    <b>Q: 会被 App 检测到吗？</b><br>A: 修改的是系统定位接口，常规 App 无法区分；但部分金融/风控类 App 有自己的检测手段，不保证 100% 过。<br><br>
    <b>Q: iOS 升级后还能用吗？</b><br>A: 大版本升级前建议先咨询客服，我们会跟进适配。<br><br>
    <b>Q: Apple 如果封堵了怎么办？</b><br>A: 本服务依赖 Apple 定位接口。如因 Apple 调整导致服务不可用，按剩余天数比例退款。<br><br>
    <b>Q: 可以退款吗？</b><br>A: 配置成功前全额退；配置成功后按未使用天数比例退。
  </div>
</div>
<div class="note">WLOC · 仅供学习测试使用<br>请勿用于欺诈、作弊等违法用途</div>
</div></body></html>`;
}

/* ---------------- /api/parse: 地图分享链接 → 经纬度 ----------------
 * GET /api/parse?url=<分享链接>
 * 流程: 提取链接 → 跟随跳转(短链) → 抠坐标 → 中国境内 GCJ-02→WGS-84 → 返回 JSON
 * 全程无存储、无日志、无缓存,处理完即丢。
 */
async function handleApiParse(url) {
	const headers = { "Content-Type": "application/json;charset=utf-8", "Access-Control-Allow-Origin": "*" };
	const input = (url.searchParams.get("url") || "").trim();
	if (!input) return jsonResp({ error: "missing url parameter" }, 400, headers);
	const link = extractFirstUrl(input);
	if (!link) return jsonResp({ error: "no url found in input" }, 400, headers);

	// 跟跳转(自动跟随),拿到最终 URL(高德短链的真实坐标藏在跳转之后)
	let finalUrl = link;
	try {
		const resp = await fetch(link, {
			redirect: "follow",
			headers: { "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15" },
		});
		if (resp.url) finalUrl = resp.url;
	} catch (e) { /* 网络失败则用原始链接继续解析 */ }

	const found = parseCoordinates(finalUrl) || parseCoordinates(link);
	if (!found) return jsonResp({ error: "no coordinates found", url: finalUrl }, 422, headers);

	let latitude = found.latitude;
	let longitude = found.longitude;
	let system = found.system;
	let converted = false;
	// 中国境内的 GCJ-02 偏移坐标 → 转 WGS-84;境外跳过换算原样返回
	if (system === "gcj02" && !outOfChina(longitude, latitude)) {
		const w = gcj02ToWgs84(longitude, latitude);
		longitude = w.longitude;
		latitude = w.latitude;
		converted = true;
		system = "wgs84";
	}
	// 坐标合法性兜底: 经度归一化到 [-180,180]; 纬度超限则拒绝, 避免存入无效坐标导致定位失效
	longitude = ((longitude % 360) + 540) % 360 - 180;
	if (!(latitude >= -90 && latitude <= 90)) {
		return jsonResp({ error: "latitude out of range", latitude: latitude, longitude: longitude }, 422, headers);
	}
	return jsonResp({
		latitude: latitude,
		longitude: longitude,
		lat: latitude,
		lng: longitude,
		system: system,
		converted: converted,
		source: found.source,
	}, 200, headers);
}

function jsonResp(obj, status, headers) {
	return new Response(JSON.stringify(obj), { status: status, headers: headers });
}

// 输入可能是"文本夹链接"(链接混在分享文本里),抠出第一个 http(s) 链接
function extractFirstUrl(text) {
	// 先直接匹配:保留 %20 等合法编码,避免解码后在空格处截断 URL
	// (Apple /place?address=... 链接里全是 %20,旧逻辑会把它截断成半截)
	let m = text.match(/https?:\/\/[^\s"'<>]+/i);
	if (m) return m[0];
	// 直接匹配失败:可能是整段分享文本被二次编码过,解码后再试一次
	try {
		const d = decodeURIComponent(text);
		m = d.match(/https?:\/\/[^\s"'<>]+/i);
		if (m) return m[0];
	} catch (e) { /* 忽略 */ }
	return null;
}

// 从 URL 里抠坐标,注意各家的经纬度顺序不同
function parseCoordinates(u) {
	let m;
	// Apple 地图: ?coordinate=纬度,经度
	m = u.match(/[?&]coordinate=(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)/i);
	if (m) return { latitude: +m[1], longitude: +m[2], system: "gcj02", source: "apple" };
	// 高德: p=经度,纬度 / dest=经度,纬度
	m = u.match(/[?&](?:p|dest)=(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)/i);
	if (m) return { longitude: +m[1], latitude: +m[2], system: "gcj02", source: "amap" };
	// Google 地图: @纬度,经度,
	m = u.match(/@(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)(?:,|\/|$|\?)/);
	if (m) return { latitude: +m[1], longitude: +m[2], system: "gcj02", source: "google" };
	// 通用: ?q=纬度,经度 / ?ll=纬度,经度
	m = u.match(/[?&](?:q|ll)=(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)/i);
	if (m) return { latitude: +m[1], longitude: +m[2], system: "gcj02", source: "generic" };
	return null;
}

/* ---------------- 坐标系换算 ---------------- */
const COORD_PI = Math.PI;
const COORD_A = 6378245.0;
const COORD_EE = 0.00669342162296594323;

function outOfChina(lng, lat) {
	return lng < 72.004 || lng > 137.8347 || lat < 0.8293 || lat > 55.8271;
}

function transformLat(lng, lat) {
	let ret = -100.0 + 2.0 * lng + 3.0 * lat + 0.2 * lat * lat + 0.1 * lng * lat + 0.2 * Math.sqrt(Math.abs(lng));
	ret += (20.0 * Math.sin(6.0 * lng * COORD_PI) + 20.0 * Math.sin(2.0 * lng * COORD_PI)) * 2.0 / 3.0;
	ret += (20.0 * Math.sin(lat * COORD_PI) + 40.0 * Math.sin(lat / 3.0 * COORD_PI)) * 2.0 / 3.0;
	ret += (160.0 * Math.sin(lat / 12.0 * COORD_PI) + 320 * Math.sin(lat * COORD_PI / 30.0)) * 2.0 / 3.0;
	return ret;
}

function transformLng(lng, lat) {
	let ret = 300.0 + lng + 2.0 * lat + 0.1 * lng * lng + 0.1 * lng * lat + 0.1 * Math.sqrt(Math.abs(lng));
	ret += (20.0 * Math.sin(6.0 * lng * COORD_PI) + 20.0 * Math.sin(2.0 * lng * COORD_PI)) * 2.0 / 3.0;
	ret += (20.0 * Math.sin(lng * COORD_PI) + 40.0 * Math.sin(lng / 3.0 * COORD_PI)) * 2.0 / 3.0;
	ret += (150.0 * Math.sin(lng / 12.0 * COORD_PI) + 300.0 * Math.sin(lng / 30.0 * COORD_PI)) * 2.0 / 3.0;
	return ret;
}

// GCJ-02 → WGS-84
function gcj02ToWgs84(lng, lat) {
	let dlat = transformLat(lng - 105.0, lat - 35.0);
	let dlng = transformLng(lng - 105.0, lat - 35.0);
	const radlat = lat / 180.0 * COORD_PI;
	let magic = Math.sin(radlat);
	magic = 1 - COORD_EE * magic * magic;
	const sqrtmagic = Math.sqrt(magic);
	dlat = (dlat * 180.0) / ((COORD_A * (1 - COORD_EE)) / (magic * sqrtmagic) * COORD_PI);
	dlng = (dlng * 180.0) / ((COORD_A / sqrtmagic) * Math.cos(radlat) * COORD_PI);
	const mglat = lat + dlat;
	const mglng = lng + dlng;
	return { longitude: lng * 2 - mglng, latitude: lat * 2 - mglat };
}

function servePage(url) {
	const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>WLOC Location Spoofer</title>
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="WLOC">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
<style>
:root { --blue:#007aff; --green:#34c759; --red:#ff3b30; --gray:#8e8e93; --bg:#f2f2f7; --orange:#ff9500; }
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:-apple-system,system-ui,"SF Pro","Helvetica Neue",sans-serif; background:var(--bg); }
#map { height:50vh; width:100%; min-height:250px; }
.panel { padding:16px; max-width:600px; margin:0 auto; }
.card { background:#fff; border-radius:12px; padding:16px; margin-bottom:12px; box-shadow:0 1px 3px rgba(0,0,0,.08); }
.card h3 { font-size:15px; font-weight:600; margin-bottom:10px; }
.coords { font-family:"SF Mono",monospace; font-size:14px; color:#333; padding:8px 12px; background:var(--bg); border-radius:8px; word-break:break-all; }
.row { display:flex; gap:8px; margin-top:10px; flex-wrap:wrap; }
.btn { flex:1; min-width:100px; padding:12px 16px; border:none; border-radius:10px; font-size:14px; font-weight:500; cursor:pointer; transition:all .15s; }
.btn-primary { background:var(--blue); color:#fff; }
.btn-primary:active { background:#005bb5; transform:scale(.97); }
.btn-secondary { background:#e5e5ea; color:#333; }
.btn-secondary:active { background:#d1d1d6; transform:scale(.97); }
.btn-danger { background:var(--red); color:#fff; }
.btn-danger:active { background:#d63027; transform:scale(.97); }
.btn.success { background:var(--green); color:#fff; }
.btn-sm { flex:none; min-width:auto; padding:6px 12px; font-size:12px; border-radius:8px; }
.input-row { display:flex; gap:8px; margin-top:10px; }
.input-row input { flex:1; padding:10px 12px; border:1px solid #d1d1d6; border-radius:8px; font-size:14px; outline:none; min-width:0; }
.input-row input:focus { border-color:var(--blue); }
.status { font-size:12px; color:var(--gray); margin-top:8px; text-align:center; }
.error-banner { background:var(--red); color:#fff; padding:14px 16px; border-radius:12px; margin-bottom:12px; font-size:14px; line-height:1.5; display:none; }
.error-banner b { display:block; margin-bottom:4px; }
.toast { position:fixed; top:60px; left:50%; transform:translateX(-50%); background:rgba(0,0,0,.8); color:#fff; padding:10px 20px; border-radius:20px; font-size:14px; opacity:0; transition:opacity .3s; pointer-events:none; z-index:9999; max-width:90vw; text-align:center; }
.toast.show { opacity:1; }
.active-loc { background:var(--bg); border-radius:8px; padding:10px 12px; font-size:13px; color:#333; }
.active-loc .label { font-size:11px; color:var(--gray); margin-bottom:4px; }
.active-loc .value { font-family:"SF Mono",monospace; font-size:13px; }
.fav-list { max-height:240px; overflow-y:auto; }
.fav-item { display:flex; align-items:center; gap:8px; padding:10px 12px; background:var(--bg); border-radius:8px; margin-bottom:6px; cursor:pointer; transition:background .15s; }
.fav-item:active { background:#e0e0e5; }
.fav-item .fav-info { flex:1; min-width:0; }
.fav-item .fav-name { font-size:14px; font-weight:500; color:#333; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.fav-item .fav-coords { font-size:11px; color:var(--gray); font-family:"SF Mono",monospace; margin-top:2px; }
.fav-item .fav-active { font-size:10px; color:var(--green); font-weight:600; }
.fav-item .fav-del { flex:none; width:28px; height:28px; border:none; border-radius:50%; background:transparent; color:var(--red); font-size:16px; cursor:pointer; display:flex; align-items:center; justify-content:center; transition:background .15s; }
.fav-item .fav-del:hover { background:rgba(255,59,48,.1); }
.fav-empty { text-align:center; color:var(--gray); font-size:13px; padding:16px 0; }
.fav-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; }
.fav-header h3 { margin-bottom:0; }
.modal-overlay { position:fixed; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,.4); z-index:10000; display:none; align-items:center; justify-content:center; padding:20px; }
.modal-overlay.show { display:flex; }
.modal { background:#fff; border-radius:16px; padding:20px; width:100%; max-width:340px; }
.modal h3 { font-size:17px; font-weight:600; margin-bottom:16px; text-align:center; }
.modal input { width:100%; padding:12px; border:1px solid #d1d1d6; border-radius:10px; font-size:15px; outline:none; margin-bottom:12px; }
.modal input:focus { border-color:var(--blue); }
.modal .modal-btns { display:flex; gap:8px; }
.modal .modal-btns .btn { padding:12px; }
.layer-switch { position:absolute; top:10px; right:10px; z-index:1000; display:flex; gap:4px; background:rgba(255,255,255,.92); border-radius:8px; padding:4px; box-shadow:0 2px 8px rgba(0,0,0,.15); }
.layer-btn { border:none; background:transparent; padding:6px 10px; border-radius:6px; font-size:12px; font-weight:500; color:#333; cursor:pointer; transition:all .15s; white-space:nowrap; }
.layer-btn.active { background:var(--blue); color:#fff; }
.layer-btn:active { transform:scale(.95); }
.lang-switch { position:absolute; top:10px; left:10px; z-index:1000; display:flex; gap:2px; background:rgba(255,255,255,.92); border-radius:8px; padding:4px; box-shadow:0 2px 8px rgba(0,0,0,.15); }
.lang-btn { border:none; background:transparent; padding:6px 11px; border-radius:6px; font-size:12px; font-weight:600; color:#333; cursor:pointer; transition:all .15s; }
.lang-btn.active { background:var(--blue); color:#fff; }
.lang-btn:active { transform:scale(.95); }
@media(max-width:480px) { #map { height:44vh; } .panel { padding:12px; } .layer-btn { padding:5px 7px; font-size:11px; } }
</style>
</head>
<body>
<div style="position:relative">
<div id="map"></div>
<div class="lang-switch">
  <button class="lang-btn" data-lang="zh" onclick="setLang('zh')">中</button>
  <button class="lang-btn" data-lang="en" onclick="setLang('en')">EN</button>
</div>
<div class="layer-switch">
  <button class="layer-btn active" data-layer="satellite" data-i18n="layer_satellite" onclick="switchLayer('satellite')">Satellite</button>
  <button class="layer-btn" data-layer="wgs84" onclick="switchLayer('wgs84')">WGS84</button>
  <button class="layer-btn" data-layer="amap" data-i18n="layer_amap" onclick="switchLayer('amap')">Amap</button>
  <button class="layer-btn" data-layer="voyager" data-i18n="layer_color" onclick="switchLayer('voyager')">Color</button>
  <button class="layer-btn" data-layer="standard" data-i18n="layer_standard" onclick="switchLayer('standard')">Standard</button>
  <button class="layer-btn" data-layer="dark" data-i18n="layer_dark" onclick="switchLayer('dark')">Dark</button>
</div>
</div>
<div class="panel">
  <div class="error-banner" id="errorBanner" data-i18n-html="err_html"></div>
  <div class="card">
    <h3 data-i18n="choose_title">Choose target location</h3>
    <div class="coords" id="coords">Tap the map or use the tools below to pick a location</div>
    <div class="row">
      <button class="btn btn-primary" id="saveBtn" data-i18n="save" onclick="save()">Save to Device</button>
      <button class="btn btn-secondary" data-i18n="add_fav" onclick="addFav()">Add Favorite</button>
      <button class="btn btn-secondary" data-i18n="locate" onclick="locateMe()">Current Location</button>
    </div>
  </div>
  <div class="card">
    <div class="fav-header">
      <h3 data-i18n="fav_title">Favorites</h3>
      <button class="btn btn-sm btn-secondary" data-i18n="clear_all" onclick="clearAllFav()" id="clearAllBtn" style="display:none">Clear All</button>
    </div>
    <div id="favList" class="fav-list"></div>
  </div>
  <div class="card">
    <h3 data-i18n="active_title">Active coordinates</h3>
    <div class="active-loc" id="activeLoc">
      <div class="label" data-i18n="active_label">Device persisted data (wloc_settings)</div>
      <div class="value" id="activeValue">Querying...</div>
    </div>
    <div class="row">
      <button class="btn btn-sm btn-secondary" data-i18n="refresh" onclick="queryActive()">Refresh</button>
      <button class="btn btn-sm btn-danger" data-i18n="clear_data" onclick="clearActive()">Clear Data</button>
    </div>
  </div>
  <div class="card">
    <h3 data-i18n="paste_title">Paste map link</h3>
    <div class="input-row">
      <input id="urlInput" data-i18n-ph="paste_ph" placeholder="Apple/Google/Amap map link or coordinates" />
      <button class="btn btn-secondary" style="flex:none;min-width:56px" data-i18n="parse" onclick="parseUrl()">Parse</button>
    </div>
    <div style="font-size:11px;color:var(--gray);margin-top:6px" data-i18n="paste_hint">Supports Apple Maps · Google Maps · Amap · Baidu · coordinate text</div>
  </div>
  <div class="card">
    <h3 data-i18n="search_title">Search place</h3>
    <div class="input-row">
      <input id="searchInput" data-i18n-ph="search_ph" placeholder="Enter a place name (e.g. The Bund, Shanghai)" />
      <button class="btn btn-secondary" style="flex:none;min-width:56px" data-i18n="search" onclick="searchPlace()">Search</button>
    </div>
  </div>
  <div class="status" id="status">Pick a location, then tap "Save to Device" to write it to your proxy tool</div>
</div>
<div class="toast" id="toast"></div>
<div class="modal-overlay" id="favModal">
  <div class="modal">
    <h3 data-i18n="modal_title">Add this location to favorites</h3>
    <input id="favNameInput" data-i18n-ph="modal_ph" placeholder="Enter a label (e.g. Office, Home)" maxlength="30" />
    <div style="font-size:12px;color:var(--gray);margin-bottom:12px;text-align:center" id="favModalCoords"></div>
    <div class="modal-btns">
      <button class="btn btn-secondary" data-i18n="cancel" onclick="closeFavModal()">Cancel</button>
      <button class="btn btn-primary" data-i18n="save_short" onclick="confirmFav()">Save</button>
    </div>
  </div>
</div>
<script>
const SAVE_API = 'https://gs-loc.apple.com/wloc-settings/save';
const FAV_KEY = 'wloc_favorites';
const LANG_KEY = 'wloc_lang';
let lat = 22.544577, lon = 113.94114;
let selected = false;
let activeLon = null, activeLat = null, activeAcc = null, activeStatus = 'querying';
let savedLon = null, savedLat = null, savedTimeStr = '';

/* ---- i18n ---- */
const I18N = {
  zh: {
    title: 'WLOC 虚拟定位',
    layer_satellite: '卫星', layer_amap: '高德', layer_color: '彩色', layer_standard: '标准', layer_dark: '暗色',
    err_html: '<b>模块未生效</b>请检查以下配置：<br>1. 已安装并启用 WLOC 定位模块<br>2. MITM 已开启且信任证书<br>3. MITM 主机名包含 gs-loc.apple.com<br>4. 当前网络已走代理',
    choose_title: '选择目标位置',
    coords_hint: '点击地图或使用下方工具选择位置',
    save: '储存到设备', add_fav: '收藏位置', locate: '当前位置',
    fav_title: '收藏的位置', clear_all: '清空全部',
    active_title: '当前生效坐标', active_label: '设备持久化数据 (wloc_settings)',
    refresh: '刷新', clear_data: '清除数据',
    paste_title: '粘贴地图链接', paste_ph: 'Apple/Google/高德地图链接 或 经纬度', parse: '解析',
    paste_hint: '支持 Apple Maps · Google Maps · 高德 · 百度 · 坐标文本',
    search_title: '搜索地点', search_ph: '输入地名（如: 上海外滩）', search: '搜索',
    status_hint: '选好位置后点击「储存到设备」写入代理工具',
    modal_title: '收藏此位置', modal_ph: '输入备注名称（如: 公司、家）', cancel: '取消', save_short: '保存',
    lon: '经度', lat: '纬度', acc: '精度',
    querying: '查询中...', no_saved: '无已保存的坐标', query_failed: '查询失败 (需要代理模块支持)', cleared: '已清除',
    fav_empty: '暂无收藏，选好位置后点击「收藏位置」',
    active_now: '✓ 当前生效', del: '删除',
    pick_first: '请先在地图上选择一个位置',
    enter_label: '请输入备注名称',
    added: function(n){ return '已收藏: ' + n; },
    deleted: function(n){ return '已删除: ' + n; },
    clear_fav_confirm: '确定清空所有收藏？', all_cleared: '已清空所有收藏',
    clear_confirm: '确定清除设备上已保存的坐标？清除后将使用模块默认参数或停止修改定位。',
    dev_cleared: '已清除设备坐标',
    clear_failed: function(e){ return '清除失败: ' + e; },
    clear_failed_cfg: '清除失败 - 请检查模块配置',
    saving: '储存中...', saved: '✓ 已储存',
    written: function(lo, la, ts){ return '✓ 已写入: ' + lo.toFixed(6) + ', ' + la.toFixed(6) + ' · ' + ts; },
    saved_toast: '✓ 坐标已写入设备，下次定位生效',
    save_failed: '✗ 储存失败 - 请检查模块配置', write_failed: '写入失败',
    no_geo: '浏览器不支持定位', getting_loc: '获取位置中...', got_loc: '已获取当前位置',
    loc_failed: function(m){ return '定位失败: ' + m; },
    paste_first: '请粘贴地图链接或坐标', parse_failed: '无法解析坐标，请检查链接格式',
    parsed: function(lo, la){ return '已解析: ' + lo.toFixed(4) + ', ' + la.toFixed(4); },
    enter_place: '请输入地名', searching: '搜索中...',
    not_found: function(q){ return '未找到: ' + q; }, search_failed: '搜索失败'
  },
  en: {
    title: 'WLOC Location Spoofer',
    layer_satellite: 'Satellite', layer_amap: 'Amap', layer_color: 'Color', layer_standard: 'Standard', layer_dark: 'Dark',
    err_html: '<b>Module not active</b>Please check the following:<br>1. The WLOC location module is installed and enabled<br>2. MITM is on and the certificate is trusted<br>3. The MITM hostname list includes gs-loc.apple.com<br>4. The current network is routed through the proxy',
    choose_title: 'Choose target location',
    coords_hint: 'Tap the map or use the tools below to pick a location',
    save: 'Save to Device', add_fav: 'Add Favorite', locate: 'Current Location',
    fav_title: 'Favorites', clear_all: 'Clear All',
    active_title: 'Active coordinates', active_label: 'Device persisted data (wloc_settings)',
    refresh: 'Refresh', clear_data: 'Clear Data',
    paste_title: 'Paste map link', paste_ph: 'Apple / Google / Amap map link or coordinates', parse: 'Parse',
    paste_hint: 'Supports Apple Maps · Google Maps · Amap · Baidu · coordinate text',
    search_title: 'Search place', search_ph: 'Enter a place name (e.g. The Bund, Shanghai)', search: 'Search',
    status_hint: 'Pick a location, then tap "Save to Device" to write it to your proxy tool',
    modal_title: 'Add this location to favorites', modal_ph: 'Enter a label (e.g. Office, Home)', cancel: 'Cancel', save_short: 'Save',
    lon: 'Lon', lat: 'Lat', acc: 'Accuracy',
    querying: 'Querying...', no_saved: 'No saved coordinates', query_failed: 'Query failed (requires the proxy module)', cleared: 'Cleared',
    fav_empty: 'No favorites yet. Pick a location and tap "Add Favorite".',
    active_now: '✓ Active now', del: 'Delete',
    pick_first: 'Please pick a location on the map first',
    enter_label: 'Please enter a label',
    added: function(n){ return 'Added: ' + n; },
    deleted: function(n){ return 'Deleted: ' + n; },
    clear_fav_confirm: 'Clear all favorites?', all_cleared: 'All favorites cleared',
    clear_confirm: 'Clear the coordinates saved on the device? After clearing, the module default parameters will be used or location spoofing will stop.',
    dev_cleared: 'Device coordinates cleared',
    clear_failed: function(e){ return 'Clear failed: ' + e; },
    clear_failed_cfg: 'Clear failed - please check the module configuration',
    saving: 'Saving...', saved: '✓ Saved',
    written: function(lo, la, ts){ return '✓ Written: ' + lo.toFixed(6) + ', ' + la.toFixed(6) + ' · ' + ts; },
    saved_toast: '✓ Coordinates written to device, effective on next location fix',
    save_failed: '✗ Save failed - please check the module configuration', write_failed: 'Write failed',
    no_geo: 'Browser does not support geolocation', getting_loc: 'Getting location...', got_loc: 'Current location acquired',
    loc_failed: function(m){ return 'Location failed: ' + m; },
    paste_first: 'Please paste a map link or coordinates', parse_failed: 'Could not parse coordinates, please check the link format',
    parsed: function(lo, la){ return 'Parsed: ' + lo.toFixed(4) + ', ' + la.toFixed(4); },
    enter_place: 'Please enter a place name', searching: 'Searching...',
    not_found: function(q){ return 'Not found: ' + q; }, search_failed: 'Search failed'
  }
};

function detectLang() {
  try {
    const saved = localStorage.getItem(LANG_KEY);
    if (saved === 'zh' || saved === 'en') return saved;
  } catch(e) {}
  return 'zh'; // default to Chinese; tap EN to switch (remembered per browser)
}
let lang = detectLang();

function t(key) {
  const v = I18N[lang][key];
  if (typeof v === 'function') return v.apply(null, Array.prototype.slice.call(arguments, 1));
  return v === undefined ? key : v;
}

function applyI18n() {
  document.documentElement.lang = (lang === 'zh' ? 'zh-CN' : 'en');
  document.title = t('title');
  document.querySelectorAll('[data-i18n]').forEach(function(el){ el.textContent = t(el.getAttribute('data-i18n')); });
  document.querySelectorAll('[data-i18n-ph]').forEach(function(el){ el.setAttribute('placeholder', t(el.getAttribute('data-i18n-ph'))); });
  document.querySelectorAll('[data-i18n-html]').forEach(function(el){ el.innerHTML = t(el.getAttribute('data-i18n-html')); });
  document.querySelectorAll('.lang-btn').forEach(function(b){ b.classList.toggle('active', b.getAttribute('data-lang') === lang); });
  updateCoords();
  updateStatus();
  renderActive();
  renderFavs();
}

function setLang(l) {
  lang = l;
  try { localStorage.setItem(LANG_KEY, l); } catch(e) {}
  applyI18n();
}

const map = L.map('map').setView([lat, lon], 13);
const tiles = {
  satellite: L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {maxZoom:19, attribution:'ArcGIS'}),
  wgs84: L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}', {maxZoom:19, attribution:'ArcGIS WGS84'}),
  standard: L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom:19, attribution:'\\u00a9 OSM'}),
  dark: L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {maxZoom:19, attribution:'\\u00a9 Carto'}),
  amap: L.tileLayer('https://webst0{s}.is.autonavi.com/appmaptile?style=6&x={x}&y={y}&z={z}', {maxZoom:18, subdomains:'1234', attribution:'\\u00a9 Amap'}),
  voyager: L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png', {maxZoom:19, attribution:'\\u00a9 Carto'})
};
let currentLayer = tiles.satellite;
currentLayer.addTo(map);
function switchLayer(name) {
  map.removeLayer(currentLayer);
  currentLayer = tiles[name];
  currentLayer.addTo(map);
  document.querySelectorAll('.layer-btn').forEach(b => b.classList.toggle('active', b.dataset.layer === name));
}
let marker = L.marker([lat, lon], {draggable:true}).addTo(map);

marker.on('dragend', e => { const p=e.target.getLatLng(); setPos(p.lat, p.lng); });
map.on('click', e => { setPos(e.latlng.lat, e.latlng.lng); });

function updateCoords() {
  document.getElementById('coords').textContent = selected
    ? (t('lon') + ' ' + lon.toFixed(6) + '  ' + t('lat') + ' ' + lat.toFixed(6))
    : t('coords_hint');
}

function updateStatus() {
  document.getElementById('status').textContent = (savedLon !== null)
    ? t('written', savedLon, savedLat, savedTimeStr)
    : t('status_hint');
}

function setPos(newLat, newLon) {
  lat = newLat; lon = ((newLon % 360) + 540) % 360 - 180; selected = true;
  marker.setLatLng([lat, lon]);
  updateCoords();
}

function moveTo(newLat, newLon, zoom) {
  setPos(newLat, newLon);
  map.setView([lat, lon], zoom || 15);
}

function toast(msg, ms) {
  const t2 = document.getElementById('toast');
  t2.textContent = msg; t2.classList.add('show');
  setTimeout(() => t2.classList.remove('show'), ms || 2500);
}

function showError(show) {
  document.getElementById('errorBanner').style.display = show ? 'block' : 'none';
}

/* ---- Favorites (localStorage) ---- */
function getFavs() {
  try { return JSON.parse(localStorage.getItem(FAV_KEY)) || []; } catch(e) { return []; }
}
function saveFavs(favs) {
  localStorage.setItem(FAV_KEY, JSON.stringify(favs));
}

function renderFavs() {
  const favs = getFavs();
  const el = document.getElementById('favList');
  const clearBtn = document.getElementById('clearAllBtn');
  clearBtn.style.display = favs.length ? '' : 'none';
  if (!favs.length) {
    el.innerHTML = '<div class="fav-empty">' + escHtml(t('fav_empty')) + '<\\/div>';
    return;
  }
  el.innerHTML = favs.map((f, i) => {
    const isActive = activeLon !== null && Math.abs(f.lon - activeLon) < 0.000001 && Math.abs(f.lat - activeLat) < 0.000001;
    return '<div class="fav-item" onclick="loadFav(' + i + ')">' +
      '<div class="fav-info">' +
        '<div class="fav-name">' + escHtml(f.name) + '<\\/div>' +
        '<div class="fav-coords">' + f.lon.toFixed(6) + ', ' + f.lat.toFixed(6) + '<\\/div>' +
        (isActive ? '<div class="fav-active">' + escHtml(t('active_now')) + '<\\/div>' : '') +
      '<\\/div>' +
      '<button class="fav-del" onclick="event.stopPropagation();delFav(' + i + ')" title="' + escHtml(t('del')) + '">\\u00d7<\\/button>' +
    '<\\/div>';
  }).join('');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function addFav() {
  if (!selected) { toast(t('pick_first')); return; }
  document.getElementById('favModalCoords').textContent = lon.toFixed(6) + ', ' + lat.toFixed(6);
  document.getElementById('favNameInput').value = '';
  document.getElementById('favModal').classList.add('show');
  setTimeout(() => document.getElementById('favNameInput').focus(), 100);
}

function closeFavModal() {
  document.getElementById('favModal').classList.remove('show');
}

function confirmFav() {
  const name = document.getElementById('favNameInput').value.trim();
  if (!name) { toast(t('enter_label')); return; }
  const favs = getFavs();
  favs.push({ name, lon, lat, time: new Date().toISOString() });
  saveFavs(favs);
  closeFavModal();
  renderFavs();
  toast(t('added', name));
}

function loadFav(i) {
  const favs = getFavs();
  if (!favs[i]) return;
  moveTo(favs[i].lat, favs[i].lon, 15);
  toast(favs[i].name + ' (' + favs[i].lon.toFixed(4) + ', ' + favs[i].lat.toFixed(4) + ')');
}

function delFav(i) {
  const favs = getFavs();
  if (!favs[i]) return;
  const name = favs[i].name;
  favs.splice(i, 1);
  saveFavs(favs);
  renderFavs();
  toast(t('deleted', name));
}

function clearAllFav() {
  if (!confirm(t('clear_fav_confirm'))) return;
  saveFavs([]);
  renderFavs();
  toast(t('all_cleared'));
}

/* ---- Active location query ---- */
function renderActive() {
  const el = document.getElementById('activeValue');
  if (activeStatus === 'ok') {
    el.textContent = t('lon') + ' ' + activeLon.toFixed(6) + '  ' + t('lat') + ' ' + activeLat.toFixed(6) + (activeAcc ? ('  ' + t('acc') + ' ' + activeAcc + 'm') : '');
  } else if (activeStatus === 'none') {
    el.textContent = t('no_saved');
  } else if (activeStatus === 'failed') {
    el.textContent = t('query_failed');
  } else if (activeStatus === 'cleared') {
    el.textContent = t('cleared');
  } else {
    el.textContent = t('querying');
  }
}

function queryActive() {
  activeStatus = 'querying';
  renderActive();
  fetch(SAVE_API + '?action=query', { method:'GET', mode:'cors', cache:'no-store' })
    .then(r => r.json())
    .then(d => {
      if (d.success && d.longitude && d.latitude) {
        activeLon = parseFloat(d.longitude);
        activeLat = parseFloat(d.latitude);
        activeAcc = d.accuracy || null;
        activeStatus = 'ok';
      } else {
        activeLon = null; activeLat = null; activeAcc = null;
        activeStatus = 'none';
      }
      renderActive();
      renderFavs();
    })
    .catch(() => { activeStatus = 'failed'; renderActive(); });
}

function clearActive() {
  if (!confirm(t('clear_confirm'))) return;
  fetch(SAVE_API + '?action=clear', { method:'GET', mode:'cors', cache:'no-store' })
    .then(r => r.json())
    .then(d => {
      if (d.success) {
        activeLon = null; activeLat = null; activeAcc = null;
        activeStatus = 'cleared';
        renderActive();
        renderFavs();
        toast(t('dev_cleared'));
      } else { toast(t('clear_failed', d.error || ''), 3000); }
    })
    .catch(() => { toast(t('clear_failed_cfg'), 3000); });
}

/* ---- Save to device ---- */
async function save() {
  if (!selected) { toast(t('pick_first')); return; }
  const btn = document.getElementById('saveBtn');
  btn.textContent = t('saving'); btn.disabled = true;
  showError(false);
  try {
    const r = await fetch(SAVE_API + '?lon=' + lon + '&lat=' + lat + '&acc=25', {
      method: 'GET', mode: 'cors', cache: 'no-store'
    });
    const d = await r.json();
    if (d.success) {
      activeLon = lon; activeLat = lat; activeAcc = 25; activeStatus = 'ok';
      savedLon = lon; savedLat = lat; savedTimeStr = new Date().toLocaleTimeString();
      btn.textContent = t('saved'); btn.className = 'btn btn-primary success';
      updateStatus();
      renderActive();
      renderFavs();
      toast(t('saved_toast'));
      setTimeout(() => { btn.textContent = t('save'); btn.className='btn btn-primary'; btn.disabled=false; }, 2500);
    } else {
      throw new Error(d.error || t('write_failed'));
    }
  } catch(e) {
    btn.textContent = t('save'); btn.className = 'btn btn-primary'; btn.disabled = false;
    showError(true);
    toast(t('save_failed'), 4000);
  }
}

function locateMe() {
  if (!navigator.geolocation) return toast(t('no_geo'));
  toast(t('getting_loc'));
  navigator.geolocation.getCurrentPosition(
    pos => { moveTo(pos.coords.latitude, pos.coords.longitude, 16); toast(t('got_loc')); },
    err => toast(t('loc_failed', err.message), 3000),
    { enableHighAccuracy:true, timeout:10000 }
  );
}

function parseMapUrl(text) {
  let m;
  m = text.match(/ll=([0-9.-]+),([0-9.-]+)/);
  if (m) return { lat: parseFloat(m[1]), lon: parseFloat(m[2]) };
  m = text.match(/@([0-9.-]+),([0-9.-]+)/);
  if (m) return { lat: parseFloat(m[1]), lon: parseFloat(m[2]) };
  m = text.match(/lnglat=([0-9.-]+),([0-9.-]+)/);
  if (m) return { lat: parseFloat(m[2]), lon: parseFloat(m[1]) };
  m = text.match(/(?:location|center)=([0-9.-]+),([0-9.-]+)/);
  if (m) return { lat: parseFloat(m[2]), lon: parseFloat(m[1]) };
  m = text.match(/([0-9]+\\.[0-9]+)[,\\s]+([0-9]+\\.[0-9]+)/);
  if (m) {
    const a = parseFloat(m[1]), b = parseFloat(m[2]);
    if (a < 90 && b > 90) return { lat: a, lon: b };
    if (b < 90 && a > 90) return { lat: b, lon: a };
    return { lat: a, lon: b };
  }
  return null;
}

function parseUrl() {
  const input = document.getElementById('urlInput').value.trim();
  if (!input) return toast(t('paste_first'));
  const result = parseMapUrl(input);
  if (!result) { toast(t('parse_failed'), 3000); return; }
  moveTo(result.lat, result.lon, 15);
  toast(t('parsed', result.lon, result.lat));
}

async function searchPlace() {
  const q = document.getElementById('searchInput').value.trim();
  if (!q) return toast(t('enter_place'));
  toast(t('searching'));
  try {
    const r = await fetch('https://nominatim.openstreetmap.org/search?format=json&limit=1&q='+encodeURIComponent(q));
    const results = await r.json();
    if (!results.length) { toast(t('not_found', q), 3000); return; }
    const p = results[0];
    moveTo(parseFloat(p.lat), parseFloat(p.lon), 15);
    toast(p.display_name.slice(0, 40));
  } catch(e) { toast(t('search_failed'), 3000); }
}

document.addEventListener('paste', e => {
  const text = (e.clipboardData||window.clipboardData).getData('text');
  if (text && (text.includes('map') || text.includes('loc') || text.includes('lnglat') || /[0-9]+\\.[0-9]+/.test(text))) {
    document.getElementById('urlInput').value = text;
    setTimeout(parseUrl, 200);
  }
});
document.getElementById('searchInput').addEventListener('keydown', e => { if(e.key==='Enter') searchPlace(); });
document.getElementById('urlInput').addEventListener('keydown', e => { if(e.key==='Enter') parseUrl(); });
document.getElementById('favNameInput').addEventListener('keydown', e => { if(e.key==='Enter') confirmFav(); });

applyI18n();
queryActive();
<\/script>
</body>
</html>`;

	return new Response(html, {
		headers: { "Content-Type": "text/html;charset=utf-8", "Cache-Control": "no-cache" },
	});
}
