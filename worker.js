export default {
async fetch(request, env) {

const url = new URL(request.url);

// =========================
// POST /post  (ساخت پست)
// =========================
if (url.pathname === "/post" && request.method === "POST") {

const data = await request.json();

const text = data.text || "";
const user = data.user || "unknown";

const message =
`📌 POST
👤 ${user}
📝 ${text}
`;

await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
method: "POST",
headers: {"Content-Type": "application/json"},
body: JSON.stringify({
chat_id: env.CHAT_ID,
text: message
})
});

return new Response(JSON.stringify({
ok: true,
status: "posted"
}), {
headers: {"Content-Type": "application/json"}
});
}

// =========================
// GET /health (تست)
// =========================
if (url.pathname === "/health") {
return new Response("Vasl API is running");
}

return new Response("Not Found", {status: 404});
}
};
