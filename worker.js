// ---------- تنظیمات کلی ----------
// مالک سایت: تنها کسی که می‌تونه ادمین‌های دیگه رو ارتقا/عزل کنه و همیشه دسترسی کامل ادمین داره
const SUPER_ADMIN_USERNAME = "Aghey";

// فقط این دامنه‌ها اجازه دارن از مرورگر به این ورکر درخواست بزنن
const ALLOWED_ORIGINS = ["https://oldvasl.github.io"];

// بر اساس Origin درخواست، هدرهای CORS مناسب رو می‌سازه
// (اگه Origin توی لیست مجاز نبود، هدر Allow-Origin اصلاً ست نمی‌شه؛
//  یعنی مرورگر خودش جلوی خوندن پاسخ رو برای اون سایت‌ها می‌گیره)
function corsHeadersFor(request) {
  const origin = request.headers.get("Origin");
  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }
  return headers;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function bufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// undefined رو به null تبدیل می‌کنه، چون D1 با undefined خطا می‌ده
function bind(stmt, args) {
  return stmt.bind(...args.map((v) => (v === undefined ? null : v)));
}

// ================= پوش نوتیفیکیشن (Web Push، بدون کتابخونه، فقط با Web Crypto) =================
// نیازمندیِ تنظیمات ورکر (از داشبورد Cloudflare، بخش Settings > Variables):
//   VAPID_PUBLIC_KEY  = "BAD4XiVtPogFVjWF4CBIoKzfwp1DouspsYByGHvgzaYgW7vntQP18phaHvKrfKvFkTEZ4b6zUEC5GyG2nPG9xx0"
//   VAPID_PRIVATE_KEY = "EpGuyb_YcuvU1r3iuxzImHTYQ7Vlv6onz1nGAS_jSJM"   (این رو به‌صورت Secret بذار، نه متغیر عادی)
//   VAPID_SUBJECT     = "mailto:you@example.com"  (یه ایمیل یا لینک تماس؛ کلادفلر/مرورگرها بهش نیازی ندارن ولی استاندارد الزامیه)
// جدول لازم توی D1 (یک‌بار توی کنسول D1 اجرا کن):
//   CREATE TABLE IF NOT EXISTS push_subscriptions (
//     id TEXT PRIMARY KEY,
//     username TEXT NOT NULL,
//     endpoint TEXT NOT NULL UNIQUE,
//     p256dh TEXT NOT NULL,
//     auth TEXT NOT NULL,
//     created_at INTEGER NOT NULL
//   );
//   CREATE INDEX IF NOT EXISTS idx_push_subs_username ON push_subscriptions (username);

// ================= عنوان کوتاه پست (حداکثر ۱۵ کاراکتر) =================
// جدول posts از قبل توی D1 وجود داره، فقط این ستون رو (یک‌بار، توی کنسول D1) اضافه کن:
//   ALTER TABLE posts ADD COLUMN title TEXT;

function base64UrlToUint8Array(base64Url) {
  const padding = "=".repeat((4 - (base64Url.length % 4)) % 4);
  const base64 = (base64Url + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}

function uint8ArrayToBase64Url(bytes) {
  let str = "";
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

// کلید خصوصی VAPID رو (که فقط بخش d رو ذخیره کردیم) به یه CryptoKey قابل امضا تبدیل می‌کنه
async function importVapidPrivateKey(env) {
  const pub = base64UrlToUint8Array(env.VAPID_PUBLIC_KEY); // 65 بایت: 0x04 || X || Y
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: uint8ArrayToBase64Url(pub.slice(1, 33)),
    y: uint8ArrayToBase64Url(pub.slice(33, 65)),
    d: env.VAPID_PRIVATE_KEY,
    ext: true,
  };
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}

// JWT امضاشده‌ی VAPID برای هدر Authorization
async function buildVapidJwt(env, audience) {
  const header = { typ: "JWT", alg: "ES256" };
  const payload = {
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: env.VAPID_SUBJECT || "mailto:admin@example.com",
  };
  const enc = new TextEncoder();
  const toB64Url = (obj) => uint8ArrayToBase64Url(enc.encode(JSON.stringify(obj)));
  const signingInput = `${toB64Url(header)}.${toB64Url(payload)}`;
  const privateKey = await importVapidPrivateKey(env);
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    enc.encode(signingInput)
  );
  return `${signingInput}.${uint8ArrayToBase64Url(new Uint8Array(signature))}`;
}

// رمزنگاری بدنه‌ی پیام طبق RFC 8291 (aes128gcm) با کلیدهای مرورگر کاربر (p256dh و auth)
async function encryptPushPayload(subscription, payloadObj) {
  const uaPublicBytes = base64UrlToUint8Array(subscription.p256dh);
  const authSecret = base64UrlToUint8Array(subscription.auth);
  const plaintext = new TextEncoder().encode(JSON.stringify(payloadObj));

  const uaPublicKey = await crypto.subtle.importKey(
    "raw", uaPublicBytes, { name: "ECDH", namedCurve: "P-256" }, false, []
  );
  const ephemeralKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
  );
  const asPublicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeralKeyPair.publicKey));

  const sharedSecretBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: uaPublicKey }, ephemeralKeyPair.privateKey, 256
  );
  const sharedSecret = new Uint8Array(sharedSecretBits);

  async function hmacSha256(keyBytes, msgBytes) {
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, msgBytes));
  }
  async function hkdfExpand(prk, info, length) {
    const key = await crypto.subtle.importKey("raw", prk, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const t1 = new Uint8Array(await crypto.subtle.sign("HMAC", key, concatBytes(info, new Uint8Array([1]))));
    return t1.slice(0, length);
  }

  // مرحله‌ی اول: استخراج IKM از راز مشترک با auth_secret به‌عنوان salt (طبق RFC 8291)
  const enc = new TextEncoder();
  const prkKey = await hmacSha256(authSecret, sharedSecret);
  const keyInfo = concatBytes(enc.encode("WebPush: info\0"), uaPublicBytes, asPublicRaw);
  const ikm = await hkdfExpand(prkKey, keyInfo, 32);

  // مرحله‌ی دوم: استخراج CEK و nonce طبق RFC 8188 (aes128gcm)
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmacSha256(salt, ikm);
  const cekBytes = await hkdfExpand(prk, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonceBytes = await hkdfExpand(prk, enc.encode("Content-Encoding: nonce\0"), 12);

  const cekKey = await crypto.subtle.importKey("raw", cekBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const recordContent = concatBytes(plaintext, new Uint8Array([2])); // 0x02 = آخرین (و تنها) رکورد
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonceBytes }, cekKey, recordContent)
  );

  const rs = new Uint8Array([0, 0, 16, 0]); // record size = 4096 (big-endian)
  const header = concatBytes(salt, rs, new Uint8Array([asPublicRaw.length]), asPublicRaw);
  return concatBytes(header, ciphertext);
}

// ارسال واقعی یک پوش به یک subscription؛ خروجی true/false برای موفقیت
async function sendWebPush(env, subscription, payloadObj) {
  if (!env.VAPID_PRIVATE_KEY || !env.VAPID_PUBLIC_KEY) return { ok: false, gone: false };
  try {
    const endpointUrl = new URL(subscription.endpoint);
    const audience = `${endpointUrl.protocol}//${endpointUrl.host}`;
    const jwt = await buildVapidJwt(env, audience);
    const body = await encryptPushPayload(subscription, payloadObj);

    const res = await fetch(subscription.endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Encoding": "aes128gcm",
        "TTL": "86400",
        "Authorization": `vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}`,
      },
      body,
    });

    // ۴۰۴/۴۱۰ یعنی subscription دیگه معتبر نیست (کاربر نوتیف رو غیرفعال کرده یا اپ رو حذف کرده)
    const gone = res.status === 404 || res.status === 410;
    return { ok: res.ok, gone };
  } catch (e) {
    return { ok: false, gone: false };
  }
}

// پوش رو به همه‌ی دستگاه‌های ثبت‌شده‌ی یک کاربر می‌فرسته؛ subscriptionهای منقضی رو خودش پاک می‌کنه
async function sendPushToUser(env, username, payloadObj) {
  try {
    const subs = await env.D1.prepare("SELECT * FROM push_subscriptions WHERE username = ?").bind(username).all();
    if (!subs.results || subs.results.length === 0) return;

    await Promise.all(
      subs.results.map(async (sub) => {
        const { gone } = await sendWebPush(env, sub, payloadObj);
        if (gone) {
          await env.D1.prepare("DELETE FROM push_subscriptions WHERE id = ?").bind(sub.id).run();
        }
      })
    );
  } catch (e) {
    // best-effort؛ خطای پوش نباید هیچ درخواستی رو خراب کنه
  }
}

// ---------- ثبت/به‌روزرسانی subscription پوش کاربر ----------
async function handleSubscribePush(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  const body = await request.json();
  const { endpoint, keys } = body || {};
  if (!endpoint || !keys || !keys.p256dh || !keys.auth) {
    return json({ error: "اطلاعات subscription ناقصه" }, 400);
  }

  const id = `${Date.now()}_${randomHex(4)}`;
  await bind(
    env.D1.prepare(
      `INSERT INTO push_subscriptions (id, username, endpoint, p256dh, auth, created_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(endpoint) DO UPDATE SET username = excluded.username, p256dh = excluded.p256dh, auth = excluded.auth`
    ),
    [id, username, endpoint, keys.p256dh, keys.auth, Date.now()]
  ).run();

  return json({ ok: true });
}

// ---------- حذف subscription (وقتی کاربر نوتیف رو خاموش می‌کنه) ----------
async function handleUnsubscribePush(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  const { endpoint } = await request.json();
  if (!endpoint) return json({ error: "endpoint لازمه" }, 400);

  await env.D1.prepare("DELETE FROM push_subscriptions WHERE endpoint = ? AND username = ?").bind(endpoint, username).run();
  return json({ ok: true });
}
// ================= پایان بخش پوش نوتیفیکیشن =================

// ---------- هش کردن پسورد (PBKDF2) ----------
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode(saltHex),
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );
  return bufferToHex(bits);
}

function randomHex(bytes = 16) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return bufferToHex(arr.buffer);
}

// ---------- تشخیص واقعیِ نوع فایل از روی بایت‌های اول (Magic Bytes) ----------
// به Content-Type اعلام‌شده توسط مرورگر به‌تنهایی اعتماد نمی‌کنیم؛ چون یه درخواست دستی (مثلاً با curl، نه از
// خودِ سایت) می‌تونه هر Content-Type دلخواهی رو ادعا کنه. این تابع خودِ محتوای فایل رو چک می‌کنه تا کسی نتونه
// مثلاً یه فایل HTML/SVG حاوی اسکریپت رو با ادعای «image/png» به سرور قالب کنه (که بعداً موقع نمایش می‌تونست
// باعث اجرای کد دلخواه (XSS) بشه).
async function detectRealMediaCategory(file) {
  const buf = new Uint8Array(await file.slice(0, 32).arrayBuffer());
  const hex = (start, len) => Array.from(buf.slice(start, start + len)).map((b) => b.toString(16).padStart(2, "0")).join("");
  const ascii = (start, len) => String.fromCharCode(...buf.slice(start, start + len));

  // عکس
  if (hex(0, 3) === "ffd8ff") return "image"; // JPEG
  if (hex(0, 4) === "89504e47") return "image"; // PNG
  if (ascii(0, 4) === "GIF8") return "image"; // GIF
  if (ascii(0, 4) === "RIFF" && ascii(8, 4) === "WEBP") return "image"; // WEBP
  if (hex(0, 2) === "424d") return "image"; // BMP

  // کانتینر ISO-BMFF (mp4/mov/m4a/heic و مشابه، همه از یه ساختار مشترک استفاده می‌کنن)
  if (ascii(4, 4) === "ftyp") {
    const brand = ascii(8, 4).trim().toLowerCase();
    if (["heic", "heix", "heif", "mif1", "avif"].includes(brand)) return "image";
    return "av"; // ویدیو یا صدا (mp4/mov/m4a همه اینجان)
  }
  if (hex(0, 4) === "1a45dfa3") return "av"; // WEBM/MKV
  if (ascii(0, 4) === "RIFF" && ascii(8, 4) === "AVI ") return "av";

  // صوت
  if (ascii(0, 3) === "ID3") return "audio"; // MP3 با تگ ID3
  if (hex(0, 2) === "fffb" || hex(0, 2) === "fff3" || hex(0, 2) === "fff2") return "audio"; // MP3 خام
  if (ascii(0, 4) === "OggS") return "audio"; // OGG
  if (ascii(0, 4) === "fLaC") return "audio"; // FLAC
  if (ascii(0, 4) === "RIFF" && ascii(8, 4) === "WAVE") return "audio"; // WAV

  return null; // هیچ امضای شناخته‌شده‌ای نداشت؛ فایل مشکوکه
}

// چک می‌کنه محتوای واقعیِ فایل با دسته‌ی ادعاشده (image/video/audio) هم‌خونی داره یا نه
async function verifyFileMatchesCategory(file, claimedCategory) {
  const real = await detectRealMediaCategory(file);
  if (!real) return false;
  if (real === claimedCategory) return true;
  if (real === "av" && (claimedCategory === "video" || claimedCategory === "audio")) return true;
  return false;
}

// ---------- محدودکننده‌ی نرخ درخواست (rate limit) روی KV؛ برای اکشن‌های پرهزینه (ثبت‌نام، پست، کامنت، آپلود) ----------
// key: شناسه‌ای که محدودیت روش اعمال می‌شه (یوزرنیم یا IP)، limit: سقف مجاز در بازه، windowSeconds: طول پنجره
// خروجی true یعنی مجازه، false یعنی به سقف رسیده و باید رد بشه
async function checkRateLimit(env, action, key, limit, windowSeconds) {
  const rlKey = `ratelimit:${action}:${key}`;
  const now = Date.now();

  let state = null;
  try {
    const raw = await env.DB.get(rlKey);
    state = raw ? JSON.parse(raw) : null;
  } catch (e) {
    state = null;
  }

  if (!state || now > state.resetAt) {
    await env.DB.put(rlKey, JSON.stringify({ count: 1, resetAt: now + windowSeconds * 1000 }), {
      expirationTtl: windowSeconds,
    });
    return true;
  }

  if (state.count >= limit) return false;

  state.count += 1;
  const remainingTtl = Math.max(1, Math.ceil((state.resetAt - now) / 1000));
  await env.DB.put(rlKey, JSON.stringify(state), { expirationTtl: remainingTtl });
  return true;
}

// ---------- شناسه‌ی IP کاربر (برای rate limit روی درخواست‌های پیش از لاگین مثل ثبت‌نام) ----------
function getClientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

// ---------- تایید توکن Cloudflare Turnstile (ضدبات، جلوی لاگین/ثبت‌نام خودکار رو می‌گیره) ----------
// اگه TURNSTILE_SECRET_KEY تو تنظیمات ورکر ست نشده باشه، این چک نادیده گرفته می‌شه (برای اینکه در حین توسعه سایت قفل نشه)
async function verifyTurnstile(token, request, env) {
  if (!env.TURNSTILE_SECRET_KEY) return true;
  if (!token) return false;

  try {
    const body = new URLSearchParams();
    body.append("secret", env.TURNSTILE_SECRET_KEY);
    body.append("response", token);
    body.append("remoteip", getClientIp(request));

    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    const data = await res.json();
    return !!data.success;
  } catch (e) {
    return false;
  }
}

// ---------- کمکی: آیا کاربر جاری ادمینه؟ (مالک سایت همیشه ادمینه) ----------
function isSuperAdmin(username) {
  return username === SUPER_ADMIN_USERNAME;
}

async function isAdminUser(env, username) {
  if (!username) return false;
  if (isSuperAdmin(username)) return true;
  const row = await env.D1.prepare("SELECT is_admin FROM users WHERE username = ?").bind(username).first();
  return !!(row && row.is_admin);
}

// ---------- گرفتن کاربر از روی توکن (و رد کردن کاربر مسدود) ----------
// سشن‌ها همچنان توی KV هستن (کاربرد اصلی KV: داده‌ی کوتاه‌مدت با TTL)
async function getUserFromToken(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return null;

  const session = await env.D1.prepare("SELECT username, expires_at FROM sessions WHERE token = ?").bind(token).first();
  if (!session) return null;
  if (session.expires_at < Date.now()) {
    // سشن منقضی شده؛ پاکش می‌کنیم و رد می‌کنیم
    await env.D1.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return null;
  }

  const user = await env.D1.prepare("SELECT banned FROM users WHERE username = ?").bind(session.username).first();
  if (!user || user.banned) return null;

  return session.username;
}

// ---------- خروج (باطل کردن توکن سمت سرور) ----------
async function handleLogout(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (token) await env.D1.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
  return json({ ok: true });
}

// فقط حروف (فارسی/انگلیسی)، عدد و آندرلاین مجازه؛ جلوی کاراکترهایی مثل کوتیشن، تگ و... رو می‌گیره
// که می‌تونستن با جاسازی نام کاربری داخل onclick سمت فرانت، باعث اجرای کد دلخواه (XSS ذخیره‌شده) بشن
const USERNAME_RE = /^[\p{L}\p{N}_]{3,20}$/u;

// ---------- ثبت‌نام ----------
async function handleRegister(request, env) {
  const ip = getClientIp(request);
  if (!(await checkRateLimit(env, "register", ip, 5, 3600))) {
    return json({ error: "تعداد ثبت‌نام از این آی‌پی زیاد بوده، یه ساعت دیگه امتحان کن" }, 429);
  }

  const { username, password, turnstileToken } = await request.json();

  if (!(await verifyTurnstile(turnstileToken, request, env))) {
    return json({ error: "تایید امنیتی انجام نشد؛ صفحه رو رفرش کن و دوباره امتحان کن" }, 400);
  }

  const PASSWORD_RE = /^(?=.*[A-Za-z])(?=.*\d).{8,}$/; // حداقل ۸ کاراکتر، شاملِ حداقل یه حرف و یه عدد
  if (!username || !password || !USERNAME_RE.test(username) || !PASSWORD_RE.test(password)) {
    return json({ error: "نام کاربری باید ۳ تا ۲۰ کاراکتر و فقط شامل حروف، عدد و _ باشه؛ رمز حداقل ۸ کاراکتر و شامل حرف و عدد باشه" }, 400);
  }

  const existing = await env.D1.prepare("SELECT username FROM users WHERE username = ?").bind(username).first();
  if (existing) {
    return json({ error: "این نام کاربری قبلاً گرفته شده" }, 409);
  }

  const salt = randomHex(16);
  const hash = await hashPassword(password, salt);
  await bind(
    env.D1.prepare("INSERT INTO users (username, salt, hash, banned, is_admin, created_at) VALUES (?, ?, ?, 0, 0, ?)"),
    [username, salt, hash, Date.now()]
  ).run();

  return json({ ok: true });
}

// ---------- ثبت تلاش ناموفق ورود؛ بعد ۵ تای پشت‌سرهم ۵ دقیقه قفل می‌شه ----------
async function registerFailedLogin(env, username) {
  const failsKey = `login_fails:${username}`;
  const raw = await env.DB.get(failsKey);
  const count = raw ? parseInt(raw, 10) : 0;
  const newCount = count + 1;

  if (newCount >= 5) {
    await env.DB.put(`login_lock:${username}`, "1", { expirationTtl: 300 }); // ۵ دقیقه قفل
    await env.DB.delete(failsKey);
  } else {
    await env.DB.put(failsKey, String(newCount), { expirationTtl: 300 }); // پنجره‌ی شمارش: ۵ دقیقه
  }
}

// ---------- ورود ----------
async function handleLogin(request, env) {
  const ip = getClientIp(request);
  // محدودیت روی خودِ IP (جدا از قفل به‌ازای هر یوزرنیم)؛ جلوی این رو می‌گیره که یه نفر
  // از یه IP، رو صدها یوزرنیم مختلف هرکدوم چندتا تلاش بزنه بدون این‌که هیچ‌جا قفل بشه
  if (!(await checkRateLimit(env, "login_ip", ip, 20, 300))) {
    return json({ error: "تعداد تلاش‌های ورود از این آی‌پی زیاد بوده، چند دقیقه دیگه امتحان کن" }, 429);
  }

  const { username, password, turnstileToken } = await request.json();
  if (!username || !password) return json({ error: "نام کاربری و رمز لازمه" }, 400);

  if (!(await verifyTurnstile(turnstileToken, request, env))) {
    return json({ error: "تایید امنیتی انجام نشد؛ صفحه رو رفرش کن و دوباره امتحان کن" }, 400);
  }

  const lockKey = `login_lock:${username}`;
  const locked = await env.DB.get(lockKey);
  if (locked) {
    return json({ error: "به خاطر تلاش‌های ناموفق زیاد، ۵ دقیقه صبر کن و دوباره امتحان کن" }, 429);
  }

  const userData = await env.D1.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
  if (!userData) {
    await registerFailedLogin(env, username);
    return json({ error: "نام کاربری یا رمز اشتباهه" }, 401);
  }

  const attemptHash = await hashPassword(password, userData.salt);
  if (attemptHash !== userData.hash) {
    await registerFailedLogin(env, username);
    return json({ error: "نام کاربری یا رمز اشتباهه" }, 401);
  }
  if (userData.banned) return json({ error: "این حساب توسط مدیر سایت مسدود شده" }, 403);

  await env.DB.delete(`login_fails:${username}`);

  const token = randomHex(24);
  // سشن به مدت ۳۰ روز معتبره
  const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
  await env.D1.prepare("INSERT INTO sessions (token, username, expires_at) VALUES (?, ?, ?)")
    .bind(token, username, expiresAt)
    .run();

  return json({ ok: true, token, username });
}

// ---------- ارسال به تلگرام (متن ساده) ----------
async function sendTelegramText(env, text) {
  const res = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: env.CHANNEL_ID, text }),
  });
  const data = await res.json();
  if (!data.ok) throw new Error(data.description || "خطای تلگرام");
  return data.result;
}

// ---------- ارسال فایل (عکس/ویدیو/سند/آهنگ) به تلگرام ----------
async function sendTelegramFile(env, method, field, file, caption, extraFields = {}) {
  const fd = new FormData();
  fd.append("chat_id", env.CHANNEL_ID);
  if (caption) fd.append("caption", caption.slice(0, 1000)); // کپشن تلگرام حداکثر ۱۰۲۴ کاراکتره
  fd.append(field, file, file.name || "upload");
  for (const [key, value] of Object.entries(extraFields)) {
    if (value) fd.append(key, value);
  }

  const res = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
    method: "POST",
    body: fd,
  });
  const data = await res.json();
  if (!data.ok) throw new Error(data.description || "خطای تلگرام");
  return data.result;
}

function extractFileId(type, result) {
  if (type === "photo" && result.photo) return result.photo[result.photo.length - 1].file_id;
  if (type === "video" && result.video) return result.video.file_id;
  if (type === "audio" && result.audio) return result.audio.file_id;
  if (type === "document" && result.document) return result.document.file_id;
  if (type === "animation" && result.animation) return result.animation.file_id;
  return null;
}

// ---------- ساخت پست جدید (متن و/یا رسانه) ----------
async function handlePost(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);
  if (!(await checkRateLimit(env, "post", username, 8, 300))) {
    return json({ error: "پست زیاد ثبت کردی، چند دقیقه دیگه امتحان کن" }, 429);
  }

  const form = await request.formData();
  const text = (form.get("text") || "").toString().trim();
  const title = (form.get("title") || "").toString().trim().slice(0, 15);
  const file = form.get("file");
  const hasFile = file && typeof file !== "string" && file.size > 0;
  const clientAudioTitle = (form.get("audio_title") || "").toString().trim().slice(0, 60);
  const clientAudioPerformer = (form.get("audio_performer") || "").toString().trim().slice(0, 60);
  const audioCoverFile = form.get("audio_cover");
  const hasAudioCover = audioCoverFile && typeof audioCoverFile !== "string" && audioCoverFile.size > 0
    && audioCoverFile.size <= 5 * 1024 * 1024;

  if (!text && !hasFile) return json({ error: "پست نمی‌تونه خالی باشه" }, 400);
  if (text.length > 2000) return json({ error: "متن خیلی طولانیه" }, 400);
  if (title.length > 15) return json({ error: "عنوان نباید بیشتر از ۱۵ کاراکتر باشه" }, 400);
  if (hasFile && file.size > 20 * 1024 * 1024) {
    return json({ error: "حجم فایل نباید بیشتر از ۲۰ مگابایت باشه" }, 400);
  }

  if (hasFile && !/^(image|video|audio)\//.test(file.type)) {
    return json({ error: "فقط عکس، ویدیو و آهنگ قابل آپلوده" }, 400);
  }
  if (hasFile && !(await verifyFileMatchesCategory(file, file.type.split("/")[0]))) {
    return json({ error: "محتوای فایل با نوع اعلام‌شده‌اش مطابقت نداره" }, 400);
  }

  const caption = text ? `${username}\n\n${text}` : username;
  let type = "text";
  let result;
  let audioCoverFileId = null;

  try {
    if (hasFile && file.type.startsWith("image/")) {
      type = "photo";
      result = await sendTelegramFile(env, "sendPhoto", "photo", file, caption);
    } else if (hasFile && file.type.startsWith("video/")) {
      type = "video";
      result = await sendTelegramFile(env, "sendVideo", "video", file, caption);
    } else if (hasFile && file.type.startsWith("audio/")) {
      type = "audio";
      // اگه از خود فایل (تگ ID3) عنوان/خواننده واقعی استخراج شده، همونا رو صریح می‌فرستیم
      // وگرنه تلگرام خودش سعی می‌کنه از تگ ID3 فایل استخراج کنه
      result = await sendTelegramFile(env, "sendAudio", "audio", file, caption, {
        title: clientAudioTitle,
        performer: clientAudioPerformer,
      });
      // کاور واقعی استخراج‌شده از تگ ID3 رو جدا آپلود می‌کنیم تا مطمئن باشیم عکس واقعی خود آهنگه
      if (hasAudioCover && (await verifyFileMatchesCategory(audioCoverFile, "image"))) {
        try {
          const coverResult = await sendTelegramFile(env, "sendPhoto", "photo", audioCoverFile, `کاور — ${username}`);
          audioCoverFileId = extractFileId("photo", coverResult);
        } catch (photoErr) {
          // بعضی کاورها رو تلگرام به‌عنوان «عکس» قبول نمی‌کنه (مثلاً JPEG با پروفایل رنگی CMYK یا ابعاد نامتعارف
          // که تو کاورهای MP3 زیاد پیش میاد). به‌جای از دست دادن کاور، همون فایل رو به‌عنوان سند می‌فرستیم؛
          // چون موقع نمایش فقط بایت‌های خام فایل رو با تگ <img> نشون می‌دیم، فرقی نداره تلگرام داخلی
          // اسمش رو «عکس» گذاشته باشه یا «سند»
          try {
            const coverDocResult = await sendTelegramFile(env, "sendDocument", "document", audioCoverFile, `کاور — ${username}`);
            audioCoverFileId = extractFileId("document", coverDocResult);
          } catch (docErr) {
            console.error("خطای آپلود کاور آهنگ (هم به‌شکل عکس هم سند شکست خورد):", photoErr.message, "|", docErr.message);
          }
        }
      }
    } else {
      type = "text";
      result = await sendTelegramText(env, caption);
    }
  } catch (err) {
    console.error("خطای ارسال پست به تلگرام:", err);
    return json({ error: "ارسال پست ناموفق بود، دوباره امتحان کن" }, 502);
  }

  const id = `${Date.now()}_${randomHex(4)}`;
  const post = {
    id,
    username,
    text,
    title: title || null,
    type,
    file_id: extractFileId(type, result),
    message_id: result.message_id,
    date: Date.now(),
    audio_title: null,
    audio_performer: null,
    audio_thumb: null,
    video_thumb: null,
  };
  if (type === "audio" && result.audio) {
    post.audio_title = clientAudioTitle || result.audio.title || null;
    post.audio_performer = clientAudioPerformer || result.audio.performer || null;
    post.audio_thumb = audioCoverFileId || (result.audio.thumb && result.audio.thumb.file_id) || null;
  }
  if (type === "video" && result.video) {
    // تلگرام خودش موقع آپلود ویدیو یه فریم رو به‌عنوان تامبنیل می‌سازه؛ همون رو ذخیره می‌کنیم
    // تا موقع نمایش پست، قبل از اینکه خودِ ویدیو لود بشه، به‌جای صفحه‌ی سیاه یه عکس نشون بدیم
    const thumb = result.video.thumb || result.video.thumbnail || null;
    post.video_thumb = (thumb && thumb.file_id) || null;
  }

  await bind(
    env.D1.prepare(
      `INSERT INTO posts (id, username, text, title, type, file_id, message_id, date, upvotes, downvotes, likes, audio_title, audio_performer, audio_thumb, video_thumb)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?, ?, ?)`
    ),
    [post.id, post.username, post.text, post.title, post.type, post.file_id, post.message_id, post.date, post.audio_title, post.audio_performer, post.audio_thumb, post.video_thumb]
  ).run();

  return json({ ok: true, post });
}

// ---------- پروکسی گرفتن فایل از تلگرام (بدون افشای توکن) ----------
async function handleMedia(fileId, env, request) {
  if (!fileId) return json({ error: "شناسه فایل لازمه" }, 400);

  const infoRes = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/getFile?file_id=${fileId}`);
  const info = await infoRes.json();
  if (!info.ok) return json({ error: "فایل پیدا نشد" }, 404);

  // اگه مرورگر برای سیک‌کردنِ سیک‌بار، یه بازه‌ی خاص از بایت‌های فایل رو خواسته (هدر Range)،
  // عیناً همون بازه رو از تلگرام هم می‌خوایم — نه کل فایل رو از اول — تا فقط از همونجا دانلود/پخش بشه
  // و مرورگر مجبور نشه (چون جواب کامل ۲۰۰ گرفته، نه ۲۰۶ بخشی) دوباره از صفر شروع کنه
  const rangeHeader = request ? request.headers.get("Range") : null;
  const telegramReqHeaders = {};
  if (rangeHeader) telegramReqHeaders["Range"] = rangeHeader;

  const fileRes = await fetch(
    `https://api.telegram.org/file/bot${env.BOT_TOKEN}/${info.result.file_path}`,
    { headers: telegramReqHeaders }
  );

  const headers = new Headers();
  headers.set("Content-Type", fileRes.headers.get("Content-Type") || "application/octet-stream");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Cache-Control", "public, max-age=86400");
  headers.set("Accept-Ranges", "bytes"); // به مرورگر می‌گیم می‌تونه هر بازه‌ای از فایل رو جدا بخواد (سیک واقعی)

  const contentLength = fileRes.headers.get("Content-Length");
  if (contentLength) headers.set("Content-Length", contentLength);
  const contentRange = fileRes.headers.get("Content-Range");
  if (contentRange) headers.set("Content-Range", contentRange);

  // اگه درخواست Range بوده و تلگرام هم بخشی (۲۰۶) جواب داده، همون استاتوس رو عیناً برمی‌گردونیم
  const status = rangeHeader && fileRes.status === 206 ? 206 : 200;
  return new Response(fileRes.body, { status, headers });
}

const MAX_STICKERS_PER_USER = 10;

// ---------- آپلود استیکر شخصی (عکس یا گیف) به تلگرام؛ سقف ۱۰ تا برای هر کاربر، عمومی و قابل استفاده برای همه ----------
async function handleUploadSticker(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);
  if (!(await checkRateLimit(env, "sticker_upload", username, 10, 600))) {
    return json({ error: "آپلود استیکر زیاد بوده، چند دقیقه دیگه امتحان کن" }, 429);
  }

  const countRow = await env.D1.prepare("SELECT COUNT(*) as c FROM stickers WHERE username = ?").bind(username).first();
  if (countRow && countRow.c >= MAX_STICKERS_PER_USER) {
    return json({ error: `حداکثر ${MAX_STICKERS_PER_USER} استیکر شخصی می‌تونی داشته باشی` }, 400);
  }

  const form = await request.formData();
  const file = form.get("file");
  if (!file || typeof file === "string" || file.size === 0) {
    return json({ error: "فایلی انتخاب نشده" }, 400);
  }
  if (file.size > 5 * 1024 * 1024) {
    return json({ error: "حجم استیکر نباید بیشتر از ۵ مگابایت باشه" }, 400);
  }
  if (!/^image\//.test(file.type)) {
    return json({ error: "فقط عکس یا گیف قابل استفاده به‌عنوان استیکره" }, 400);
  }
  if (!(await verifyFileMatchesCategory(file, "image"))) {
    return json({ error: "محتوای فایل با نوع اعلام‌شده‌اش مطابقت نداره" }, 400);
  }

  let name = (form.get("name") || "").toString().trim().slice(0, 40);
  if (!name) name = null;

  const isAnimated = file.type === "image/gif";
  let fileId = null;

  try {
    if (isAnimated) {
      // گیف رو با sendAnimation می‌فرستیم تا تلگرام حالت متحرکش رو حفظ کنه (خروجی mp4 بی‌صدا)
      const result = await sendTelegramFile(env, "sendAnimation", "animation", file, undefined);
      fileId = extractFileId("animation", result);
    } else {
      const result = await sendTelegramFile(env, "sendPhoto", "photo", file, undefined);
      fileId = extractFileId("photo", result);
    }
  } catch (err) {
    console.error("خطای ارسال استیکر به تلگرام:", err);
    return json({ error: "آپلود استیکر ناموفق بود، دوباره امتحان کن" }, 502);
  }

  if (!fileId) return json({ error: "دریافت فایل استیکر ناموفق بود" }, 502);

  const id = `${Date.now()}_${randomHex(4)}`;
  const date = Date.now();
  await bind(
    env.D1.prepare("INSERT INTO stickers (id, username, file_id, is_animated, date, name) VALUES (?, ?, ?, ?, ?, ?)"),
    [id, username, fileId, isAnimated ? 1 : 0, date, name]
  ).run();

  return json({ ok: true, sticker: { id, username, file_id: fileId, is_animated: isAnimated ? 1 : 0, date, name } });
}

// ---------- لیست استیکرهای شخصیِ عمومیِ همه‌ی کاربران (صفحه‌بندی‌شده + قابل جستجو، برای پشتیبانی از تعداد زیاد) ----------
async function handleGetStickers(request, env) {
  const url = new URL(request.url);
  const page = Math.max(parseInt(url.searchParams.get("page") || "1", 10), 1);
  const pageSize = Math.min(Math.max(parseInt(url.searchParams.get("pageSize") || "60", 10), 1), 100);
  const search = (url.searchParams.get("search") || "").toLowerCase().trim();
  const usernameFilter = url.searchParams.get("username");

  const where = [];
  const params = [];
  if (search) {
    where.push("(LOWER(name) LIKE ? OR LOWER(username) LIKE ?)");
    params.push(`%${search}%`, `%${search}%`);
  }
  if (usernameFilter) {
    where.push("username = ?");
    params.push(usernameFilter);
  }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const totalRow = await bind(env.D1.prepare(`SELECT COUNT(*) as c FROM stickers ${whereSql}`), params).first();
  const total = totalRow ? totalRow.c : 0;

  const start = (page - 1) * pageSize;
  const rows = await bind(
    env.D1.prepare(`SELECT id, username, file_id, is_animated, name, date FROM stickers ${whereSql} ORDER BY date DESC LIMIT ? OFFSET ?`),
    [...params, pageSize, start]
  ).all();

  return json({
    ok: true,
    stickers: rows.results || [],
    total,
    page,
    pageSize,
    hasMore: start + pageSize < total,
  });
}

// ---------- حذف استیکر (صاحبش یا ادمین) ----------
async function handleDeleteSticker(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  if (!id) return json({ error: "شناسه استیکر لازمه" }, 400);

  const sticker = await env.D1.prepare("SELECT * FROM stickers WHERE id = ?").bind(id).first();
  if (!sticker) return json({ error: "استیکر پیدا نشد" }, 404);

  if (sticker.username !== username && !(await isAdminUser(env, username))) {
    return json({ error: "فقط صاحب استیکر یا ادمین می‌تونه حذفش کنه" }, 403);
  }

  await env.D1.prepare("DELETE FROM stickers WHERE id = ?").bind(id).run();
  return json({ ok: true });
}

// دامنه‌ی مجاز برای استیکرهای پیش‌فرض (فایل‌های خام ریپو گیت‌هاب) — برای جلوگیری از ثبت لینک دلخواه به‌جای استیکر
const ALLOWED_STICKER_URL_HOST = "raw.githubusercontent.com";

// ---------- ساخت اعلان برای یک کاربر ----------
async function createNotification(env, toUsername, data) {
  if (!toUsername) return;
  const id = `${Date.now()}_${randomHex(4)}`;
  await bind(
    env.D1.prepare(
      "INSERT INTO notifications (id, to_username, type, post_id, from_username, text, comment_id, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ),
    [id, toUsername, data.type, data.post_id || null, data.from_username || null, data.text || null, data.comment_id || null, Date.now()]
  ).run();

  // ارسال پوش نوتیفیکیشن به موازات ذخیره‌ی اعلان (best-effort؛ نبود subscription یا خطای شبکه چیزی رو خراب نمی‌کنه)
  const pushMessages = {
    comment: (d) => `${d.from_username} روی پستت کامنت گذاشت`,
    reply: (d) => `${d.from_username} به کامنتت جواب داد`,
    vote: (d) => `${d.from_username} به پستت رای مثبت داد`,
  };
  const bodyBuilder = pushMessages[data.type];
  if (bodyBuilder) {
    await sendPushToUser(env, toUsername, {
      title: "دهات",
      body: bodyBuilder(data),
      url: data.post_id ? `index.html?post=${data.post_id}` : "index.html",
      tag: `notif-${data.type}-${data.post_id || ""}`,
    });
  }
}

// ---------- ثبت کامنت جدید (متنی یا استیکری) ----------
async function handleAddComment(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);
  if (!(await checkRateLimit(env, "comment", username, 20, 300))) {
    return json({ error: "کامنت زیاد ثبت کردی، چند دقیقه دیگه امتحان کن" }, 429);
  }

  const body = await request.json();
  const { post_id, parent_id, sticker_id, sticker_url } = body;
  if (!post_id) return json({ error: "شناسه پست لازمه" }, 400);

  let type = "text";
  let text = (body.text || "").toString().trim();
  let stickerSrc = null;
  let stickerIsExternal = 0;
  let stickerIsVideo = 0;

  if (sticker_id) {
    // استیکر شخصی: باید توی جدول stickers ثبت شده باشه (فایل روی تلگرام)
    const sticker = await env.D1.prepare("SELECT * FROM stickers WHERE id = ?").bind(sticker_id).first();
    if (!sticker) return json({ error: "استیکر پیدا نشد" }, 404);
    type = "sticker";
    text = "";
    stickerSrc = sticker.file_id;
    stickerIsExternal = 0;
    stickerIsVideo = sticker.is_animated ? 1 : 0;
  } else if (sticker_url) {
    // استیکر پیش‌فرض: لینک مستقیم از پوشه‌ی stickers توی ریپو گیت‌هاب
    let parsed;
    try {
      parsed = new URL(sticker_url.toString());
    } catch (e) {
      return json({ error: "لینک استیکر نامعتبره" }, 400);
    }
    if (parsed.hostname !== ALLOWED_STICKER_URL_HOST) {
      return json({ error: "لینک استیکر مجاز نیست" }, 400);
    }
    type = "sticker";
    text = "";
    stickerSrc = parsed.toString();
    stickerIsExternal = 1;
    stickerIsVideo = 0;
  } else {
    if (!text) return json({ error: "متن کامنت خالیه" }, 400);
    if (text.length > 500) return json({ error: "کامنت خیلی طولانیه" }, 400);
  }

  const post = await env.D1.prepare("SELECT * FROM posts WHERE id = ?").bind(post_id).first();

  // اگه ریپلای به یه کامنت دیگه‌ست، اون کامنت رو پیدا می‌کنیم
  let parentComment = null;
  if (parent_id) {
    parentComment = await env.D1.prepare("SELECT * FROM comments WHERE id = ? AND post_id = ?").bind(parent_id, post_id).first();
  }

  // تلاش برای ثبت به صورت ریپلای زیر پست اصلی در تلگرام (best-effort، اگه شکست بخوره مشکلی نیست)
  const noticeText = type === "sticker" ? "یک استیکر فرستاد" : text;
  try {
    if (post && post.message_id) {
      const prefix = parentComment ? `ریپلای به ${parentComment.username} از طرف ${username}` : `کامنت از ${username}`;
      await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: env.CHANNEL_ID,
          text: `${prefix}:\n${noticeText}`,
          reply_to_message_id: post.message_id,
        }),
      });
    }
  } catch (err) {
    // مهم نیست؛ کامنت مستقل از تلگرام هم ذخیره می‌شه
  }

  const id = `${Date.now()}_${randomHex(4)}`;
  const comment = {
    id,
    post_id,
    username,
    text,
    date: Date.now(),
    parent_id: parentComment ? parentComment.id : null,
    type,
    sticker_src: stickerSrc,
    sticker_is_external: stickerIsExternal,
    sticker_is_video: stickerIsVideo,
  };
  await bind(
    env.D1.prepare(
      `INSERT INTO comments (id, post_id, username, text, date, parent_id, type, sticker_src, sticker_is_external, sticker_is_video)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ),
    [
      comment.id,
      comment.post_id,
      comment.username,
      comment.text,
      comment.date,
      comment.parent_id,
      comment.type,
      comment.sticker_src,
      comment.sticker_is_external,
      comment.sticker_is_video,
    ]
  ).run();

  const notifSnippet = type === "sticker" ? "🖼️ یک استیکر فرستاد" : text.slice(0, 120);

  if (parentComment) {
    // ریپلای: اعلان برای صاحب کامنت مادر (نه لزوماً صاحب پست)
    if (parentComment.username && parentComment.username !== username) {
      await createNotification(env, parentComment.username, {
        type: "reply",
        post_id,
        from_username: username,
        text: notifSnippet,
        comment_id: id,
      });
    }
  } else if (post && post.username && post.username !== username) {
    // کامنت معمولی: اعلان برای صاحب پست
    await createNotification(env, post.username, {
      type: "comment",
      post_id,
      from_username: username,
      text: notifSnippet,
      comment_id: id,
    });
  }

  return json({ ok: true, comment });
}

// ---------- گرفتن کامنت‌های یک پست ----------
async function handleGetComments(request, env) {
  const url = new URL(request.url);
  const postId = url.searchParams.get("post_id");
  if (!postId) return json({ error: "شناسه پست لازمه" }, 400);

  const viewerUsername = await getUserFromToken(request, env);

  const res = await env.D1.prepare("SELECT * FROM comments WHERE post_id = ? ORDER BY date ASC").bind(postId).all();
  const comments = res.results || [];

  if (comments.length === 0) return json({ ok: true, comments: [] });

  // آواتار نویسنده‌های این کامنت‌ها
  const uniqueUsernames = [...new Set(comments.map((c) => c.username))];
  const avatarMap = {};
  if (uniqueUsernames.length > 0) {
    const placeholders = uniqueUsernames.map(() => "?").join(",");
    const profileRows = await bind(
      env.D1.prepare(`SELECT username, avatar_file_id FROM profiles WHERE username IN (${placeholders})`),
      uniqueUsernames
    ).all();
    for (const row of profileRows.results || []) {
      if (row.avatar_file_id) avatarMap[row.username] = row.avatar_file_id;
    }
  }

  // اینکه کاربرِ درخواست‌دهنده کدوم کامنت‌ها رو لایک کرده
  let likedSet = new Set();
  if (viewerUsername) {
    const ids = comments.map((c) => c.id);
    const placeholders = ids.map(() => "?").join(",");
    const likeRows = await bind(
      env.D1.prepare(`SELECT comment_id FROM comment_likes WHERE username = ? AND comment_id IN (${placeholders})`),
      [viewerUsername, ...ids]
    ).all();
    likedSet = new Set((likeRows.results || []).map((r) => r.comment_id));
  }

  const enriched = comments.map((c) => ({
    ...c,
    avatar_file_id: avatarMap[c.username] || null,
    likes: c.likes || 0,
    edited: !!c.edited,
    liked: likedSet.has(c.id),
  }));

  return json({ ok: true, comments: enriched });
}

// ---------- لایک/آنلایک یک کامنت ----------
async function handleLikeComment(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: "درخواست نامعتبره" }, 400);
  }
  const commentId = body.comment_id;
  if (!commentId) return json({ error: "شناسه کامنت لازمه" }, 400);

  const comment = await env.D1.prepare("SELECT id FROM comments WHERE id = ?").bind(commentId).first();
  if (!comment) return json({ error: "کامنت پیدا نشد" }, 404);

  const existing = await env.D1
    .prepare("SELECT 1 FROM comment_likes WHERE comment_id = ? AND username = ?")
    .bind(commentId, username)
    .first();

  let liked;
  if (existing) {
    await env.D1.prepare("DELETE FROM comment_likes WHERE comment_id = ? AND username = ?").bind(commentId, username).run();
    await env.D1.prepare("UPDATE comments SET likes = MAX(likes - 1, 0) WHERE id = ?").bind(commentId).run();
    liked = false;
  } else {
    await env.D1.prepare("INSERT INTO comment_likes (comment_id, username) VALUES (?, ?)").bind(commentId, username).run();
    await env.D1.prepare("UPDATE comments SET likes = likes + 1 WHERE id = ?").bind(commentId).run();
    liked = true;
  }

  const updated = await env.D1.prepare("SELECT likes FROM comments WHERE id = ?").bind(commentId).first();
  return json({ ok: true, liked, likes: updated ? updated.likes : 0 });
}

// ---------- ویرایش متن یک کامنت (فقط صاحبش) ----------
async function handleEditComment(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: "درخواست نامعتبره" }, 400);
  }
  const commentId = body.comment_id;
  const text = (body.text || "").toString().trim();
  if (!commentId) return json({ error: "شناسه کامنت لازمه" }, 400);
  if (!text) return json({ error: "متن کامنت نمی‌تونه خالی باشه" }, 400);
  if (text.length > 500) return json({ error: "کامنت خیلی طولانیه" }, 400);

  const comment = await env.D1.prepare("SELECT * FROM comments WHERE id = ?").bind(commentId).first();
  if (!comment) return json({ error: "کامنت پیدا نشد" }, 404);
  if (comment.username !== username) return json({ error: "فقط صاحب کامنت می‌تونه ویرایشش کنه" }, 403);
  if (comment.type === "sticker") return json({ error: "استیکر قابل ویرایش نیست" }, 400);

  await env.D1.prepare("UPDATE comments SET text = ?, edited = 1 WHERE id = ?").bind(text, commentId).run();
  return json({ ok: true, text });
}

// ---------- حذف یک کامنت (صاحبش یا ادمین) ----------
async function handleDeleteComment(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  if (!id) return json({ error: "شناسه کامنت لازمه" }, 400);

  const comment = await env.D1.prepare("SELECT * FROM comments WHERE id = ?").bind(id).first();
  if (!comment) return json({ error: "کامنت پیدا نشد" }, 404);

  if (comment.username !== username && !(await isAdminUser(env, username))) {
    return json({ error: "فقط صاحب کامنت می‌تونه حذفش کنه" }, 403);
  }

  // ریپلای‌های مستقیمِ همین کامنت هم حذف می‌شن که یتیم نمونن
  const replies = await env.D1.prepare("SELECT id FROM comments WHERE parent_id = ?").bind(id).all();
  const allIds = [id, ...(replies.results || []).map((r) => r.id)];
  const placeholders = allIds.map(() => "?").join(",");

  await env.D1.batch([
    bind(env.D1.prepare(`DELETE FROM comments WHERE id IN (${placeholders})`), allIds),
    bind(env.D1.prepare(`DELETE FROM comment_likes WHERE comment_id IN (${placeholders})`), allIds),
  ]);

  return json({ ok: true });
}

// ---------- حذف پست ----------
async function handleDeletePost(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  if (!id) return json({ error: "شناسه پست لازمه" }, 400);

  const post = await env.D1.prepare("SELECT * FROM posts WHERE id = ?").bind(id).first();
  if (!post) return json({ error: "پست پیدا نشد" }, 404);

  if (post.username !== username && !(await isAdminUser(env, username))) {
    return json({ error: "فقط صاحب پست می‌تونه حذفش کنه" }, 403);
  }

  // تلاش برای حذف پیام از تلگرام (best-effort)
  try {
    if (post.message_id) {
      await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/deleteMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: env.CHANNEL_ID, message_id: post.message_id }),
      });
    }
  } catch (err) {
    // مهم نیست، ادامه می‌دیم
  }

  await env.D1.batch([
    env.D1.prepare("DELETE FROM posts WHERE id = ?").bind(id),
    env.D1.prepare("DELETE FROM comments WHERE post_id = ?").bind(id),
    env.D1.prepare("DELETE FROM votes WHERE post_id = ?").bind(id),
    env.D1.prepare("DELETE FROM likes WHERE post_id = ?").bind(id),
  ]);

  return json({ ok: true });
}

// ---------- گرفتن فید (با صفحه‌بندی و فیلتر رسانه/متن) ----------
// ---------- گرفتن یک پست به‌تنهایی (برای نمایش پاپ‌آپ از روی اعلان) ----------
async function handleGetSinglePost(request, env) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  if (!id) return json({ error: "شناسه پست لازمه" }, 400);

  const post = await env.D1.prepare("SELECT * FROM posts WHERE id = ?").bind(id).first();
  if (!post) return json({ error: "پست پیدا نشد" }, 404);

  const viewerUsername = await getUserFromToken(request, env);

  const profile = await env.D1.prepare("SELECT avatar_file_id FROM profiles WHERE username = ?").bind(post.username).first();

  let userVote = null;
  let liked = false;
  if (viewerUsername) {
    const [voteRow, likeRow] = await Promise.all([
      env.D1.prepare("SELECT action FROM votes WHERE post_id = ? AND username = ?").bind(id, viewerUsername).first(),
      env.D1.prepare("SELECT 1 FROM likes WHERE post_id = ? AND username = ?").bind(id, viewerUsername).first(),
    ]);
    userVote = voteRow ? voteRow.action : null;
    liked = !!likeRow;
  }

  // شماره‌ی همون پست، هم‌راستا با شماره‌گذاری فید (تعداد پست‌هایی که هم‌زمان یا زودتر ثبت شدن)
  const numberRow = await env.D1.prepare("SELECT COUNT(*) as c FROM posts WHERE date <= ?").bind(post.date).first();
  const number = numberRow ? numberRow.c : 1;

  const commentCountRow = await env.D1.prepare("SELECT COUNT(*) as c FROM comments WHERE post_id = ?").bind(id).first();

  const enrichedPost = {
    ...post,
    avatar_file_id: (profile && profile.avatar_file_id) || null,
    upvotes: post.upvotes || 0,
    downvotes: post.downvotes || 0,
    likes: post.likes || 0,
    userVote,
    liked,
    comment_count: commentCountRow ? commentCountRow.c : 0,
  };

  return json({ ok: true, post: enrichedPost, number });
}

async function handleFeed(request, env) {
  const url = new URL(request.url);
  const page = Math.max(parseInt(url.searchParams.get("page") || "1", 10), 1);
  const pageSize = Math.min(Math.max(parseInt(url.searchParams.get("pageSize") || "10", 10), 1), 50);
  const filter = url.searchParams.get("filter") || "all"; // all | media | text | audio
  const usernameFilter = url.searchParams.get("username");
  const excludeAudio = url.searchParams.get("excludeAudio") === "1";
  const sort = url.searchParams.get("sort") || "date"; // date | popular (بر اساس آپ‌ووت) | random (برای صفِ پخش رندوم)
  const orderBySql = sort === "popular" ? "upvotes DESC, date DESC" : sort === "random" ? "RANDOM()" : "date DESC";
  // لیست شناسه‌هایی که باید از نتیجه کنار گذاشته بشن (برای صفِ رندوم پلیر، تا آهنگ تکراری اضافه نشه)
  const excludeIdsParam = url.searchParams.get("exclude");
  const excludeIds = excludeIdsParam
    ? excludeIdsParam.split(",").map((s) => s.trim()).filter(Boolean).slice(0, 300)
    : [];

  // اگه توکن معتبر ارسال شده باشه، وضعیت رای/لایک همین کاربر روی پست‌ها هم برمی‌گردونیم (اختیاریه)
  const viewerUsername = await getUserFromToken(request, env);

  const where = [];
  const params = [];
  if (filter === "media") {
    where.push("type != 'text'");
  } else if (filter === "text") {
    where.push("type = 'text'");
  } else if (filter === "audio") {
    where.push("type = 'audio'");
  }
  if (excludeAudio) {
    where.push("type != 'audio'");
  }
  if (usernameFilter) {
    where.push("username = ?");
    params.push(usernameFilter);
  }
  if (excludeIds.length > 0) {
    where.push(`id NOT IN (${excludeIds.map(() => "?").join(",")})`);
    params.push(...excludeIds);
  }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const totalRow = await bind(env.D1.prepare(`SELECT COUNT(*) as c FROM posts ${whereSql}`), params).first();
  const total = totalRow ? totalRow.c : 0;

  const start = (page - 1) * pageSize;
  const pagePosts = (
    await bind(
      env.D1.prepare(`SELECT * FROM posts ${whereSql} ORDER BY ${orderBySql} LIMIT ? OFFSET ?`),
      [...params, pageSize, start]
    ).all()
  ).results || [];

  // آواتار هر کاربر رو به پست‌های همین صفحه وصل می‌کنیم (فقط برای نویسنده‌های همین صفحه، نه کل فید)
  const uniqueUsernames = [...new Set(pagePosts.map((p) => p.username))];
  const avatarMap = {};
  if (uniqueUsernames.length > 0) {
    const placeholders = uniqueUsernames.map(() => "?").join(",");
    const profileRows = await bind(
      env.D1.prepare(`SELECT username, avatar_file_id FROM profiles WHERE username IN (${placeholders})`),
      uniqueUsernames
    ).all();
    for (const row of profileRows.results || []) {
      if (row.avatar_file_id) avatarMap[row.username] = row.avatar_file_id;
    }
  }

  // وضعیت رای و لایک شخصی کاربر بازدیدکننده رو برای پست‌های همین صفحه می‌خونیم
  let voteMap = {};
  let likeMap = {};
  if (viewerUsername && pagePosts.length > 0) {
    const ids = pagePosts.map((p) => p.id);
    const placeholders = ids.map(() => "?").join(",");
    const [voteRows, likeRows] = await Promise.all([
      bind(env.D1.prepare(`SELECT post_id, action FROM votes WHERE username = ? AND post_id IN (${placeholders})`), [viewerUsername, ...ids]).all(),
      bind(env.D1.prepare(`SELECT post_id FROM likes WHERE username = ? AND post_id IN (${placeholders})`), [viewerUsername, ...ids]).all(),
    ]);
    for (const row of voteRows.results || []) voteMap[row.post_id] = row.action;
    for (const row of likeRows.results || []) likeMap[row.post_id] = true;
  }

  // تعداد کامنت‌های هر پست (شامل ریپلای‌ها) رو یک‌جا می‌گیریم، نه یکی‌یکی برای هر پست
  const commentCountMap = {};
  if (pagePosts.length > 0) {
    const ids = pagePosts.map((p) => p.id);
    const placeholders = ids.map(() => "?").join(",");
    const countRows = await bind(
      env.D1.prepare(`SELECT post_id, COUNT(*) as c FROM comments WHERE post_id IN (${placeholders}) GROUP BY post_id`),
      ids
    ).all();
    for (const row of countRows.results || []) commentCountMap[row.post_id] = row.c;
  }

  const enrichedPosts = pagePosts.map((p) => ({
    ...p,
    avatar_file_id: avatarMap[p.username] || null,
    upvotes: p.upvotes || 0,
    downvotes: p.downvotes || 0,
    likes: p.likes || 0,
    userVote: voteMap[p.id] || null,
    liked: !!likeMap[p.id],
    comment_count: commentCountMap[p.id] || 0,
  }));

  return json({
    ok: true,
    posts: enrichedPosts,
    total,
    page,
    pageSize,
    hasMore: start + pageSize < total,
  });
}

// ---------- رای دادن به پست (آپ‌ووت/داون‌ووت) ----------
async function handleVote(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: "درخواست نامعتبره" }, 400);
  }

  const postId = (body.post_id || "").toString();
  const action = (body.action || "").toString();
  if (!postId) return json({ error: "شناسه پست لازمه" }, 400);
  if (!["up", "down"].includes(action)) return json({ error: "نوع رای نامعتبره" }, 400);

  const post = await env.D1.prepare("SELECT * FROM posts WHERE id = ?").bind(postId).first();
  if (!post) return json({ error: "پست پیدا نشد" }, 404);

  let upvotes = post.upvotes || 0;
  let downvotes = post.downvotes || 0;

  const existingRow = await env.D1.prepare("SELECT action FROM votes WHERE post_id = ? AND username = ?").bind(postId, username).first();
  const existing = existingRow ? existingRow.action : null;

  let userVote;
  if (existing === action) {
    // همون رای قبلی دوباره زده شده => لغو رای
    if (action === "up") upvotes = Math.max(0, upvotes - 1);
    else downvotes = Math.max(0, downvotes - 1);
    await env.D1.prepare("DELETE FROM votes WHERE post_id = ? AND username = ?").bind(postId, username).run();
    userVote = null;
  } else {
    // یا رای قبلی نداشته، یا داشته تغییرش می‌ده
    if (existing === "up") upvotes = Math.max(0, upvotes - 1);
    else if (existing === "down") downvotes = Math.max(0, downvotes - 1);
    if (action === "up") upvotes += 1;
    else downvotes += 1;
    await env.D1.prepare("INSERT OR REPLACE INTO votes (post_id, username, action) VALUES (?, ?, ?)").bind(postId, username, action).run();
    userVote = action;
  }

  await env.D1.prepare("UPDATE posts SET upvotes = ?, downvotes = ? WHERE id = ?").bind(upvotes, downvotes, postId).run();

  // اعلان فقط برای آپ‌ووت جدید (نه لغو رای، نه داون‌ووت) و نه به خود صاحب پست
  if (userVote === "up" && existing !== "up" && post.username && post.username !== username) {
    await createNotification(env, post.username, {
      type: "vote",
      post_id: postId,
      from_username: username,
    });
  }

  return json({
    ok: true,
    upvotes,
    downvotes,
    score: upvotes - downvotes,
    userVote,
  });
}

// ---------- لایک (سیو) کردن پست ----------
async function handleLike(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: "درخواست نامعتبره" }, 400);
  }

  const postId = (body.post_id || "").toString();
  if (!postId) return json({ error: "شناسه پست لازمه" }, 400);

  const post = await env.D1.prepare("SELECT * FROM posts WHERE id = ?").bind(postId).first();
  if (!post) return json({ error: "پست پیدا نشد" }, 404);

  let likes = post.likes || 0;
  const existing = await env.D1.prepare("SELECT 1 FROM likes WHERE post_id = ? AND username = ?").bind(postId, username).first();

  let liked;
  if (existing) {
    await env.D1.prepare("DELETE FROM likes WHERE post_id = ? AND username = ?").bind(postId, username).run();
    likes = Math.max(0, likes - 1);
    liked = false;
  } else {
    await env.D1.prepare("INSERT INTO likes (post_id, username) VALUES (?, ?)").bind(postId, username).run();
    likes += 1;
    liked = true;
  }

  await env.D1.prepare("UPDATE posts SET likes = ? WHERE id = ?").bind(likes, postId).run();

  return json({ ok: true, likes, liked });
}

// ---------- گرفتن پروفایل یک کاربر (عمومی) ----------
async function handleGetProfile(request, env) {
  const url = new URL(request.url);
  const username = url.searchParams.get("username");
  if (!username) return json({ error: "نام کاربری لازمه" }, 400);

  const user = await env.D1.prepare("SELECT username FROM users WHERE username = ?").bind(username).first();
  if (!user) return json({ error: "کاربر پیدا نشد" }, 404);

  const profile = await env.D1.prepare("SELECT * FROM profiles WHERE username = ?").bind(username).first();

  // اگه بیننده لاگین کرده و پروفایل خودش نیست، چک می‌کنیم قبلاً گزارشش داده یا نه
  const viewer = await getUserFromToken(request, env);
  let reportedByMe = false;
  if (viewer && viewer !== username) {
    const existingReport = await env.D1.prepare(
      "SELECT id FROM reports WHERE reporter_username = ? AND target_username = ?"
    ).bind(viewer, username).first();
    reportedByMe = !!existingReport;
  }

  return json({
    ok: true,
    profile: {
      username,
      bio: (profile && profile.bio) || "",
      avatar_file_id: (profile && profile.avatar_file_id) || null,
      theme: (profile && profile.theme) || "purple",
      reported_by_me: reportedByMe,
    },
  });
}

// ---------- ذخیره تم انتخابی کاربر ----------
const VALID_THEMES = ["purple", "dark", "red", "blue", "teal", "emerald"];
async function handleUpdateTheme(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: "درخواست نامعتبره" }, 400);
  }

  const theme = (body.theme || "").toString();
  if (!VALID_THEMES.includes(theme)) {
    return json({ error: "تم نامعتبره" }, 400);
  }

  await env.D1.prepare(
    `INSERT INTO profiles (username, bio, avatar_file_id, theme, updated_at) VALUES (?, '', NULL, ?, ?)
     ON CONFLICT(username) DO UPDATE SET theme = excluded.theme, updated_at = excluded.updated_at`
  ).bind(username, theme, Date.now()).run();

  return json({ ok: true, theme });
}

// ---------- ذخیره پروفایل خود کاربر (بایو و/یا آواتار) ----------
async function handleUpdateProfile(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  const form = await request.formData();
  const bio = (form.get("bio") || "").toString().trim().slice(0, 300);
  const avatarFile = form.get("avatar");
  const hasAvatar = avatarFile && typeof avatarFile !== "string" && avatarFile.size > 0;

  const existing = await env.D1.prepare("SELECT * FROM profiles WHERE username = ?").bind(username).first();
  let avatarFileId = (existing && existing.avatar_file_id) || null;
  const theme = (existing && existing.theme) || "purple";

  if (hasAvatar) {
    if (!avatarFile.type.startsWith("image/")) {
      return json({ error: "آواتار باید یه فایل عکس باشه" }, 400);
    }
    if (!(await verifyFileMatchesCategory(avatarFile, "image"))) {
      return json({ error: "محتوای فایل با نوع اعلام‌شده‌اش مطابقت نداره" }, 400);
    }
    if (avatarFile.size > 5 * 1024 * 1024) {
      return json({ error: "حجم عکس آواتار نباید بیشتر از ۵ مگابایت باشه" }, 400);
    }
    if (!(await checkRateLimit(env, "avatar_upload", username, 6, 600))) {
      return json({ error: "آپدیت آواتار زیاد بوده، چند دقیقه دیگه امتحان کن" }, 429);
    }
    try {
      const result = await sendTelegramFile(env, "sendPhoto", "photo", avatarFile, `آواتار جدید — ${username}`);
      avatarFileId = extractFileId("photo", result);
    } catch (err) {
      console.error("خطای آپلود آواتار به تلگرام:", err);
      return json({ error: "آپلود آواتار ناموفق بود، دوباره امتحان کن" }, 502);
    }
  }

  await env.D1.prepare(
    `INSERT INTO profiles (username, bio, avatar_file_id, theme, updated_at) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(username) DO UPDATE SET bio = excluded.bio, avatar_file_id = excluded.avatar_file_id, updated_at = excluded.updated_at`
  ).bind(username, bio, avatarFileId, theme, Date.now()).run();

  return json({ ok: true, profile: { username, bio, avatar_file_id: avatarFileId, theme } });
}

// ---------- وضعیت ادمین‌بودن کاربر جاری ----------
async function handleAdminMe(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  const admin = await isAdminUser(env, username);
  return json({ ok: true, is_admin: admin, is_super_admin: isSuperAdmin(username) });
}

// ---------- ارتقا/عزل ادمین (فقط مالک سایت) ----------
async function handleSetAdmin(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);
  if (!isSuperAdmin(username)) return json({ error: "فقط مالک سایت می‌تونه ادمین تعیین یا عزل کنه" }, 403);

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: "درخواست نامعتبره" }, 400);
  }

  const targetUsername = (body.username || "").toString();
  const makeAdmin = !!body.is_admin;
  if (!targetUsername) return json({ error: "نام کاربری لازمه" }, 400);
  if (targetUsername === SUPER_ADMIN_USERNAME) {
    return json({ error: "مالک سایت همیشه ادمینه و نیازی به تغییر نداره" }, 400);
  }

  const existing = await env.D1.prepare("SELECT username FROM users WHERE username = ?").bind(targetUsername).first();
  if (!existing) return json({ error: "کاربر پیدا نشد" }, 404);

  await env.D1.prepare("UPDATE users SET is_admin = ? WHERE username = ?").bind(makeAdmin ? 1 : 0, targetUsername).run();

  return json({ ok: true, username: targetUsername, is_admin: makeAdmin });
}

// ---------- آمار پنل مدیریت (برای همه‌ی ادمین‌ها) ----------
async function handleAdminStats(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);
  if (!(await isAdminUser(env, username))) return json({ error: "دسترسی نداری" }, 403);

  const [userCount, postCount, commentCount] = await Promise.all([
    env.D1.prepare("SELECT COUNT(*) as c FROM users").first(),
    env.D1.prepare("SELECT COUNT(*) as c FROM posts").first(),
    env.D1.prepare("SELECT COUNT(*) as c FROM comments").first(),
  ]);

  return json({
    ok: true,
    stats: { users: userCount.c, posts: postCount.c, comments: commentCount.c },
  });
}

// ---------- لیست کاربران با قابلیت جستجو (برای همه‌ی ادمین‌ها) ----------
async function handleAdminUsers(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);
  if (!(await isAdminUser(env, username))) return json({ error: "دسترسی نداری" }, 403);

  const url = new URL(request.url);
  const search = (url.searchParams.get("search") || "").toLowerCase().trim();
  const page = Math.max(parseInt(url.searchParams.get("page") || "1", 10), 1);
  const pageSize = Math.min(Math.max(parseInt(url.searchParams.get("pageSize") || "20", 10), 1), 100);

  const where = search ? "WHERE LOWER(username) LIKE ?" : "";
  const params = search ? [`%${search}%`] : [];

  const totalRow = await bind(env.D1.prepare(`SELECT COUNT(*) as c FROM users ${where}`), params).first();
  const total = totalRow ? totalRow.c : 0;

  const start = (page - 1) * pageSize;
  const rows = await bind(
    env.D1.prepare(`SELECT username, banned, is_admin, created_at FROM users ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`),
    [...params, pageSize, start]
  ).all();

  const pageUsers = (rows.results || []).map((u) => ({
    username: u.username,
    banned: !!u.banned,
    is_admin: !!u.is_admin || isSuperAdmin(u.username),
    is_super_admin: isSuperAdmin(u.username),
    created_at: u.created_at || null,
  }));

  return json({ ok: true, users: pageUsers, total, page, pageSize, hasMore: start + pageSize < total });
}

// ---------- مسدود/رفع مسدودی یک کاربر (برای همه‌ی ادمین‌ها، با محدودیت روی خود ادمین‌ها) ----------
async function handleBanUser(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);
  if (!(await isAdminUser(env, username))) return json({ error: "دسترسی نداری" }, 403);

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: "درخواست نامعتبره" }, 400);
  }

  const targetUsername = (body.username || "").toString();
  const banned = !!body.banned;
  if (!targetUsername) return json({ error: "نام کاربری لازمه" }, 400);
  if (targetUsername === username) return json({ error: "نمی‌تونی خودت رو مسدود کنی" }, 400);
  if (isSuperAdmin(targetUsername)) return json({ error: "نمی‌شه مالک سایت رو مسدود کرد" }, 400);

  const existing = await env.D1.prepare("SELECT username, is_admin FROM users WHERE username = ?").bind(targetUsername).first();
  if (!existing) return json({ error: "کاربر پیدا نشد" }, 404);

  // فقط مالک سایت می‌تونه یک ادمین دیگه رو مسدود کنه
  if (existing.is_admin && !isSuperAdmin(username)) {
    return json({ error: "فقط مالک سایت می‌تونه ادمین‌ها رو مسدود کنه" }, 403);
  }

  await env.D1.prepare("UPDATE users SET banned = ? WHERE username = ?").bind(banned ? 1 : 0, targetUsername).run();

  return json({ ok: true, username: targetUsername, banned });
}

// ---------- گرفتن لیست اعلان‌های کاربر ----------
async function handleGetNotifications(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  const url = new URL(request.url);
  const page = Math.max(parseInt(url.searchParams.get("page") || "1", 10), 1);
  const pageSize = Math.min(Math.max(parseInt(url.searchParams.get("pageSize") || "20", 10), 1), 50);

  const totalRow = await env.D1.prepare("SELECT COUNT(*) as c FROM notifications WHERE to_username = ?").bind(username).first();
  const total = totalRow ? totalRow.c : 0;

  const start = (page - 1) * pageSize;
  const rows = await env.D1.prepare(
    "SELECT * FROM notifications WHERE to_username = ? ORDER BY date DESC LIMIT ? OFFSET ?"
  ).bind(username, pageSize, start).all();

  const lastReadRow = await env.D1.prepare("SELECT last_read FROM notif_read WHERE username = ?").bind(username).first();
  const lastRead = lastReadRow ? lastReadRow.last_read : 0;

  const unreadRow = await env.D1.prepare("SELECT COUNT(*) as c FROM notifications WHERE to_username = ? AND date > ?").bind(username, lastRead).first();
  const unreadCount = unreadRow ? unreadRow.c : 0;

  // عنوان پست‌های مرتبط با همین صفحه از اعلان‌ها رو یک‌جا می‌گیریم (نه یکی‌یکی)، تا مشخص بشه
  // هر اعلان زیر کدوم پسته — دقیقاً مثل الگوی avatarMap توی handleFeed
  const notifRows = rows.results || [];
  const uniquePostIds = [...new Set(notifRows.map((n) => n.post_id).filter(Boolean))];
  const postTitleMap = {};
  if (uniquePostIds.length > 0) {
    const placeholders = uniquePostIds.map(() => "?").join(",");
    const titleRows = await env.D1.prepare(
      `SELECT id, title FROM posts WHERE id IN (${placeholders})`
    ).bind(...uniquePostIds).all();
    for (const row of titleRows.results || []) {
      if (row.title) postTitleMap[row.id] = row.title;
    }
  }

  const pageNotifs = notifRows.map((n) => ({
    ...n,
    is_new: n.date > lastRead,
    post_title: n.post_id ? (postTitleMap[n.post_id] || null) : null,
  }));

  return json({
    ok: true,
    notifications: pageNotifs,
    total,
    page,
    pageSize,
    hasMore: start + pageSize < total,
    unread_count: unreadCount,
  });
}

// ---------- علامت‌زدن همه اعلان‌ها به‌عنوان خونده‌شده ----------
async function handleMarkNotificationsRead(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  await env.D1.prepare(
    `INSERT INTO notif_read (username, last_read) VALUES (?, ?)
     ON CONFLICT(username) DO UPDATE SET last_read = excluded.last_read`
  ).bind(username, Date.now()).run();

  return json({ ok: true });
}

// ---------- ثبت گزارش یک کاربر (هر کاربر فقط یک‌بار می‌تونه یک نفر رو گزارش بده) ----------
async function handleCreateReport(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: "درخواست نامعتبره" }, 400);
  }

  const targetUsername = (body.target_username || "").toString().trim();
  const reason = (body.reason || "").toString().trim();

  if (!targetUsername) return json({ error: "نام کاربری لازمه" }, 400);
  if (targetUsername === username) return json({ error: "نمی‌تونی خودت رو گزارش کنی" }, 400);
  if (!reason) return json({ error: "دلیل گزارش رو بنویس" }, 400);
  if (reason.length > 80) return json({ error: "توضیحات نباید بیشتر از ۸۰ کاراکتر باشه" }, 400);

  const target = await env.D1.prepare("SELECT username FROM users WHERE username = ?").bind(targetUsername).first();
  if (!target) return json({ error: "کاربر پیدا نشد" }, 404);

  const existing = await env.D1.prepare(
    "SELECT id FROM reports WHERE reporter_username = ? AND target_username = ?"
  ).bind(username, targetUsername).first();
  if (existing) return json({ error: "قبلاً این کاربر رو گزارش دادی" }, 409);

  const id = `${Date.now()}_${randomHex(4)}`;
  await bind(
    env.D1.prepare("INSERT INTO reports (id, reporter_username, target_username, reason, date) VALUES (?, ?, ?, ?, ?)"),
    [id, username, targetUsername, reason, Date.now()]
  ).run();

  return json({ ok: true });
}

// ---------- لیست گزارش‌ها (برای همه‌ی ادمین‌ها) ----------
async function handleAdminReports(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);
  if (!(await isAdminUser(env, username))) return json({ error: "دسترسی نداری" }, 403);

  const url = new URL(request.url);
  const page = Math.max(parseInt(url.searchParams.get("page") || "1", 10), 1);
  const pageSize = Math.min(Math.max(parseInt(url.searchParams.get("pageSize") || "20", 10), 1), 100);

  const totalRow = await env.D1.prepare("SELECT COUNT(*) as c FROM reports").first();
  const total = totalRow ? totalRow.c : 0;

  const start = (page - 1) * pageSize;
  const rows = await env.D1.prepare("SELECT * FROM reports ORDER BY date DESC LIMIT ? OFFSET ?")
    .bind(pageSize, start)
    .all();

  return json({ ok: true, reports: rows.results || [], total, page, pageSize, hasMore: start + pageSize < total });
}

// ---------- بستن (حذف) یک گزارش، بعد از رسیدگی (برای همه‌ی ادمین‌ها) ----------
async function handleDismissReport(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);
  if (!(await isAdminUser(env, username))) return json({ error: "دسترسی نداری" }, 403);

  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  if (!id) return json({ error: "شناسه گزارش لازمه" }, 400);

  await env.D1.prepare("DELETE FROM reports WHERE id = ?").bind(id).run();
  return json({ ok: true });
}

// ---------- تشخیص مسیر و صدا زدن هندلر مربوطه (بدون هدر CORS؛ CORS در fetch اصلی اضافه می‌شه) ----------
async function routeRequest(url, request, env) {
      if (url.pathname === "/api/register" && request.method === "POST") {
        return await handleRegister(request, env);
      }
      if (url.pathname === "/api/login" && request.method === "POST") {
        return await handleLogin(request, env);
      }
      if (url.pathname === "/api/logout" && request.method === "POST") {
        return await handleLogout(request, env);
      }
      if (url.pathname === "/api/post" && request.method === "GET") {
        return await handleGetSinglePost(request, env);
      }
      if (url.pathname === "/api/post" && request.method === "POST") {
        return await handlePost(request, env);
      }
      if (url.pathname === "/api/feed" && request.method === "GET") {
        return await handleFeed(request, env);
      }
      if (url.pathname === "/api/post" && request.method === "DELETE") {
        return await handleDeletePost(request, env);
      }
      if (url.pathname === "/api/comment" && request.method === "POST") {
        return await handleAddComment(request, env);
      }
      if (url.pathname === "/api/comment" && request.method === "DELETE") {
        return await handleDeleteComment(request, env);
      }
      if (url.pathname === "/api/comment/like" && request.method === "POST") {
        return await handleLikeComment(request, env);
      }
      if (url.pathname === "/api/comment/edit" && request.method === "POST") {
        return await handleEditComment(request, env);
      }
      if (url.pathname === "/api/sticker" && request.method === "POST") {
        return await handleUploadSticker(request, env);
      }
      if (url.pathname === "/api/stickers" && request.method === "GET") {
        return await handleGetStickers(request, env);
      }
      if (url.pathname === "/api/sticker" && request.method === "DELETE") {
        return await handleDeleteSticker(request, env);
      }
      if (url.pathname === "/api/vote" && request.method === "POST") {
        return await handleVote(request, env);
      }
      if (url.pathname === "/api/like" && request.method === "POST") {
        return await handleLike(request, env);
      }
      if (url.pathname === "/api/comments" && request.method === "GET") {
        return await handleGetComments(request, env);
      }
      if (url.pathname === "/api/profile" && request.method === "GET") {
        return await handleGetProfile(request, env);
      }
      if (url.pathname === "/api/profile" && request.method === "POST") {
        return await handleUpdateProfile(request, env);
      }
      if (url.pathname === "/api/theme" && request.method === "POST") {
        return await handleUpdateTheme(request, env);
      }
      if (url.pathname === "/api/admin/me" && request.method === "GET") {
        return await handleAdminMe(request, env);
      }
      if (url.pathname === "/api/admin/stats" && request.method === "GET") {
        return await handleAdminStats(request, env);
      }
      if (url.pathname === "/api/admin/users" && request.method === "GET") {
        return await handleAdminUsers(request, env);
      }
      if (url.pathname === "/api/admin/ban" && request.method === "POST") {
        return await handleBanUser(request, env);
      }
      if (url.pathname === "/api/admin/role" && request.method === "POST") {
        return await handleSetAdmin(request, env);
      }
      if (url.pathname === "/api/report" && request.method === "POST") {
        return await handleCreateReport(request, env);
      }
      if (url.pathname === "/api/admin/reports" && request.method === "GET") {
        return await handleAdminReports(request, env);
      }
      if (url.pathname === "/api/admin/reports" && request.method === "DELETE") {
        return await handleDismissReport(request, env);
      }
      if (url.pathname === "/api/notifications" && request.method === "GET") {
        return await handleGetNotifications(request, env);
      }
      if (url.pathname === "/api/notifications/read" && request.method === "POST") {
        return await handleMarkNotificationsRead(request, env);
      }
      if (url.pathname === "/api/push/subscribe" && request.method === "POST") {
        return await handleSubscribePush(request, env);
      }
      if (url.pathname === "/api/push/unsubscribe" && request.method === "POST") {
        return await handleUnsubscribePush(request, env);
      }
      if (url.pathname.startsWith("/api/media/") && request.method === "GET") {
        const fileId = decodeURIComponent(url.pathname.slice("/api/media/".length));
        return await handleMedia(fileId, env, request);
      }
      return json({ error: "مسیر پیدا نشد" }, 404);
}

// ---------- روتر اصلی ----------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const corsHeaders = corsHeadersFor(request);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      const response = await routeRequest(url, request, env);
      const finalHeaders = new Headers(response.headers);
      for (const [key, value] of Object.entries(corsHeaders)) {
        finalHeaders.set(key, value);
      }
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: finalHeaders,
      });
    } catch (err) {
      // جزئیات خطا فقط توی لاگ سرور (قابل مشاهده از داشبورد Cloudflare) ثبت می‌شه، نه توی پاسخ به کاربر؛
      // چون پیام خام خطا می‌تونه جزئیات داخلی (نام جدول، ساختار کوئری و...) رو لو بده
      console.error("خطای داخلی سرور:", err);
      const errResponse = json({ error: "خطای داخلی سرور رخ داد؛ لطفاً دوباره امتحان کن" }, 500);
      for (const [key, value] of Object.entries(corsHeaders)) {
        errResponse.headers.set(key, value);
      }
      return errResponse;
    }
  },
};
