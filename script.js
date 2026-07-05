const API = "https://vasling.alipviv8698.workers.dev";
let currentUser = null;

//  ورود
function login() {
    const u = document.getElementById("username").value.trim();
    const p = document.getElementById("password").value.trim();

    if (!u || !p) {
        alert("نام کاربری و رمز عبور را وارد کنید.");
        return;
    }

    currentUser = u;

    document.getElementById("loginPage").classList.remove("active");
    document.getElementById("homePage").classList.add("active");
}

// خروج
function logout() {
    currentUser = null;

    document.getElementById("homePage").classList.remove("active");
    document.getElementById("loginPage").classList.add("active");
}

// ساخت پست
async function createPost() {

    const textarea = document.getElementById("postText");
    const text = textarea.value.trim();

    if (!text) {
        alert("متن پست خالی است.");
        return;
    }

    if (text.length > 2000) {
        alert("متن پست بیش از حد طولانی است.");
        return;
    }

    try {

        const response = await fetch(API + "/post", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                text,
                user: currentUser
            })
        });

        if (!response.ok) {
            throw new Error("Server Error");
        }

        const result = await response.json();

        if (!result.ok) {
            throw new Error(result.error || "Unknown Error");
        }

        const feed = document.getElementById("feed");

        const post = document.createElement("div");
        post.className = "post";

        post.innerHTML = `
            <strong>${currentUser}</strong>
            <p>${text}</p>
        `;

        feed.prepend(post);

        textarea.value = "";

    } catch (err) {
        console.error(err);
        alert("ارسال پست ناموفق بود.");
    }

}
