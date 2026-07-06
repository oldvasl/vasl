// ---------- تنظیمات کلی ----------
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS_HEADERS },
  });
}

function bufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

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

// ---------- گرفتن کاربر از روی توکن ----------
async function getUserFromToken(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return null;
  const username = await env.DB.get(`session:${token}`);
  return username;
}

// ---------- ثبت‌نام ----------
async function handleRegister(request, env) {
  const { username, password } = await request.json();

  if (!username || !password || username.length < 3 || password.length < 6) {
    return json({ error: "نام کاربری حداقل ۳ کاراکتر و رمز حداقل ۶ کاراکتر باشه" }, 400);
  }

  const existing = await env.DB.get(`user:${username}`);
  if (existing) {
    return json({ error: "این نام کاربری قبلاً گرفته شده" }, 409);
  }

  const salt = randomHex(16);
  const hash = await hashPassword(password, salt);
  await env.DB.put(`user:${username}`, JSON.stringify({ salt, hash }));

  return json({ ok: true });
}

// ---------- ورود ----------
async function handleLogin(request, env) {
  const { username, password } = await request.json();
  if (!username || !password) return json({ error: "نام کاربری و رمز لازمه" }, 400);

  const raw = await env.DB.get(`user:${username}`);
  if (!raw) return json({ error: "نام کاربری یا رمز اشتباهه" }, 401);

  const { salt, hash } = JSON.parse(raw);
  const attemptHash = await hashPassword(password, salt);
  if (attemptHash !== hash) return json({ error: "نام کاربری یا رمز اشتباهه" }, 401);

  const token = randomHex(24);
  // سشن به مدت ۷ روز معتبره
  await env.DB.put(`session:${token}`, username, { expirationTtl: 60 * 60 * 24 * 7 });

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

// ---------- ارسال فایل (عکس/ویدیو/سند) به تلگرام ----------
async function sendTelegramFile(env, method, field, file, caption) {
  const fd = new FormData();
  fd.append("chat_id", env.CHANNEL_ID);
  if (caption) fd.append("caption", caption.slice(0, 1000)); // کپشن تلگرام حداکثر ۱۰۲۴ کاراکتره
  fd.append(field, file, file.name || "upload");

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
  if (type === "document" && result.document) return result.document.file_id;
  return null;
}

// ---------- ساخت پست جدید (متن و/یا رسانه) ----------
async function handlePost(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  const form = await request.formData();
  const text = (form.get("text") || "").toString().trim();
  const file = form.get("file");
  const hasFile = file && typeof file !== "string" && file.size > 0;

  if (!text && !hasFile) return json({ error: "پست نمی‌تونه خالی باشه" }, 400);
  if (text.length > 2000) return json({ error: "متن خیلی طولانیه" }, 400);
  if (hasFile && file.size > 20 * 1024 * 1024) {
    return json({ error: "حجم فایل نباید بیشتر از ۲۰ مگابایت باشه" }, 400);
  }

  const caption = text ? `${username}\n\n${text}` : username;
  let type = "text";
  let result;

  try {
    if (hasFile && file.type.startsWith("image/")) {
      type = "photo";
      result = await sendTelegramFile(env, "sendPhoto", "photo", file, caption);
    } else if (hasFile && file.type.startsWith("video/")) {
      type = "video";
      result = await sendTelegramFile(env, "sendVideo", "video", file, caption);
    } else if (hasFile) {
      type = "document";
      result = await sendTelegramFile(env, "sendDocument", "document", file, caption);
    } else {
      type = "text";
      result = await sendTelegramText(env, caption);
    }
  } catch (err) {
    return json({ error: "ارسال به تلگرام ناموفق بود: " + err.message }, 502);
  }

  const id = `${Date.now()}_${randomHex(4)}`;
  const post = {
    id,
    username,
    text,
    type,
    file_id: extractFileId(type, result),
    message_id: result.message_id,
    date: Date.now(),
  };
  await env.DB.put(`post:${id}`, JSON.stringify(post));

  return json({ ok: true, post });
}

// ---------- پروکسی گرفتن فایل از تلگرام (بدون افشای توکن) ----------
async function handleMedia(fileId, env) {
  if (!fileId) return json({ error: "شناسه فایل لازمه" }, 400);

  const infoRes = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/getFile?file_id=${fileId}`);
  const info = await infoRes.json();
  if (!info.ok) return json({ error: "فایل پیدا نشد" }, 404);

  const fileRes = await fetch(`https://api.telegram.org/file/bot${env.BOT_TOKEN}/${info.result.file_path}`);
  const headers = new Headers(CORS_HEADERS);
  headers.set("Content-Type", fileRes.headers.get("Content-Type") || "application/octet-stream");
  headers.set("Cache-Control", "public, max-age=86400");
  return new Response(fileRes.body, { status: 200, headers });
}

// ---------- ثبت کامنت جدید ----------
async function handleAddComment(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  const { post_id, text } = await request.json();
  if (!post_id) return json({ error: "شناسه پست لازمه" }, 400);
  if (!text || !text.trim()) return json({ error: "متن کامنت خالیه" }, 400);
  if (text.length > 500) return json({ error: "کامنت خیلی طولانیه" }, 400);

  // تلاش برای ثبت به صورت ریپلای زیر پست اصلی در تلگرام (best-effort، اگه شکست بخوره مشکلی نیست)
  try {
    const postRaw = await env.DB.get(`post:${post_id}`);
    if (postRaw) {
      const post = JSON.parse(postRaw);
      if (post.message_id) {
        await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: env.CHANNEL_ID,
            text: `کامنت از ${username}:\n${text.trim()}`,
            reply_to_message_id: post.message_id,
          }),
        });
      }
    }
  } catch (err) {
    // مهم نیست؛ کامنت مستقل از تلگرام هم ذخیره می‌شه
  }

  const id = `${Date.now()}_${randomHex(4)}`;
  const comment = { id, post_id, username, text: text.trim(), date: Date.now() };
  await env.DB.put(`comment:${post_id}:${id}`, JSON.stringify(comment));

  return json({ ok: true, comment });
}

// ---------- گرفتن کامنت‌های یک پست ----------
async function handleGetComments(request, env) {
  const url = new URL(request.url);
  const postId = url.searchParams.get("post_id");
  if (!postId) return json({ error: "شناسه پست لازمه" }, 400);

  const list = await env.DB.list({ prefix: `comment:${postId}:` });
  const comments = [];
  for (const key of list.keys) {
    const raw = await env.DB.get(key.name);
    if (raw) comments.push(JSON.parse(raw));
  }
  comments.sort((a, b) => a.date - b.date);
  return json({ ok: true, comments });
}

// ---------- حذف پست ----------
async function handleDeletePost(request, env) {
  const username = await getUserFromToken(request, env);
  if (!username) return json({ error: "ابتدا وارد شو" }, 401);

  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  if (!id) return json({ error: "شناسه پست لازمه" }, 400);

  const raw = await env.DB.get(`post:${id}`);
  if (!raw) return json({ error: "پست پیدا نشد" }, 404);

  const post = JSON.parse(raw);
  if (post.username !== username) {
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

  await env.DB.delete(`post:${id}`);

  // حذف کامنت‌های مرتبط با این پست
  const commentList = await env.DB.list({ prefix: `comment:${id}:` });
  for (const key of commentList.keys) {
    await env.DB.delete(key.name);
  }

  return json({ ok: true });
}

// ---------- گرفتن فید (با صفحه‌بندی) ----------
async function handleFeed(request, env) {
  const url = new URL(request.url);
  const page = Math.max(parseInt(url.searchParams.get("page") || "1", 10), 1);
  const pageSize = Math.min(Math.max(parseInt(url.searchParams.get("pageSize") || "10", 10), 1), 50);

  const list = await env.DB.list({ prefix: "post:" });
  const posts = [];
  for (const key of list.keys) {
    const raw = await env.DB.get(key.name);
    if (raw) posts.push(JSON.parse(raw));
  }
  posts.sort((a, b) => b.date - a.date);

  const total = posts.length;
  const start = (page - 1) * pageSize;
  const pagePosts = posts.slice(start, start + pageSize);

  return json({
    ok: true,
    posts: pagePosts,
    total,
    page,
    pageSize,
    hasMore: start + pageSize < total,
  });
}

// ---------- روتر اصلی ----------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    try {
      if (url.pathname === "/api/register" && request.method === "POST") {
        return await handleRegister(request, env);
      }
      if (url.pathname === "/api/login" && request.method === "POST") {
        return await handleLogin(request, env);
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
      if (url.pathname === "/api/comments" && request.method === "GET") {
        return await handleGetComments(request, env);
      }
      if (url.pathname.startsWith("/api/media/") && request.method === "GET") {
        const fileId = decodeURIComponent(url.pathname.slice("/api/media/".length));
        return await handleMedia(fileId, env);
      }
      return json({ error: "مسیر پیدا نشد" }, 404);
    } catch (err) {
      return json({ error: "خطای داخلی سرور: " + err.message }, 500);
    }
  },
};
