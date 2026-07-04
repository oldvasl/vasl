let currentUser = null;
let API = "https://vasling.alipviv8698.workers.dev";
// ورود
function login(){
const u = document.getElementById("username").value;
const p = document.getElementById("password").value;

if(!u || !p){
alert("پر کن");
return;
}

currentUser = u;

document.getElementById("loginPage").classList.remove("active");
document.getElementById("homePage").classList.add("active");
}

// خروج
function logout(){
currentUser = null;

document.getElementById("homePage").classList.remove("active");
document.getElementById("loginPage").classList.add("active");
}

// ساخت پست
function createPost(){
const text = document.getElementById("postText").value;

if(!text) return;

const feed = document.getElementById("feed");

const post = document.createElement("div");
post.className = "post";

post.innerHTML = `
<strong>${currentUser}</strong>
<p>${text}</p>
`;

feed.prepend(post);

document.getElementById("postText").value = "";
}
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
