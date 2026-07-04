let API = "https://vasling.alipviv8698.workers.dev";
let currentUser = null;

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

// ساخت پست (فقط یکی!)
async function createPost(){

const text = document.getElementById("postText").value;

if(!text) return;

// ارسال به Cloudflare → Telegram
await fetch(API + "/post", {
method: "POST",
headers: {
"Content-Type": "application/json"
},
body: JSON.stringify({
text: text,
user: currentUser
})
});

// نمایش در UI
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
 
