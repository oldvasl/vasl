const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
};

export default {

async fetch(request, env) {

    if (request.method === "OPTIONS") {
        return new Response(null, {
            status: 204,
            headers: cors
        });
    }

    const url = new URL(request.url);

    // سلامت API
    if (url.pathname === "/health") {
        return new Response("Vasl API is running", {
            headers: cors
        });
    }

    // ارسال پست
    if (url.pathname === "/post" && request.method === "POST") {

        try {

            const data = await request.json();

            const text = (data.text || "").trim();
            const user = (data.user || "Unknown").trim();

            if (!text) {
                return Response.json({
                    ok: false,
                    error: "Empty text"
                }, {
                    status: 400,
                    headers: cors
                });
            }

            if (text.length > 2000) {
                return Response.json({
                    ok: false,
                    error: "Text too long"
                }, {
                    status: 400,
                    headers: cors
                });
            }

            const tg = await fetch(
                `https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        chat_id: env.CHAT_ID,
                        text:
`📌 POST

👤 ${user}

📝 ${text}`
                    })
                }
            );

            const telegram = await tg.json();

            if (!telegram.ok) {
                return Response.json({
                    ok: false,
                    error: telegram.description
                }, {
                    status: 500,
                    headers: cors
                });
            }

            return Response.json({
                ok: true,
                message_id: telegram.result.message_id
            }, {
                headers: cors
            });

        } catch (e) {

            return Response.json({
                ok: false,
                error: e.message
            }, {
                status: 500,
                headers: cors
            });

        }

    }

    return new Response("Not Found", {
        status: 404,
        headers: cors
    });

}

};
