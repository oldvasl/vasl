// ---------- سرویس‌ورکر دهات: فقط برای پوش نوتیفیکیشن ----------
// این فایل کش نمی‌کنه و آفلاین کار نمی‌کنه؛ تنها وظیفه‌اش گرفتن پوش از سرور و نمایش نوتیف واقعی روی گوشیه.

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = { title: "دهات", body: event.data ? event.data.text() : "" };
  }

  const title = data.title || "دهات";
  const options = {
    body: data.body || "",
    icon: data.icon || "icon-192.png",
    badge: "icon-192.png",
    dir: "rtl",
    lang: "fa",
    tag: data.tag || undefined,
    data: { url: data.url || "index.html" },
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

// با لمس نوتیفیکیشن، اگه تب سایت باز بود بهش فوکوس کن، وگرنه یه تب جدید باز کن
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) || "index.html";

  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if (client.url.includes("index.html") && "focus" in client) {
          if ("navigate" in client) client.navigate(targetUrl).catch(() => {});
          return client.focus();
        }
      }
      if (self.clients.openWindow) return self.clients.openWindow(targetUrl);
    })
  );
});
