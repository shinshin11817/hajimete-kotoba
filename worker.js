export default {
  async fetch(request, env) {
    const url = new URL(request.url);
 
    // D1接続確認用
    if (url.pathname === "/api/health") {
      try {
        const result = await env.DB
          .prepare("SELECT 1 AS ok")
          .first();
 
        return Response.json({
          status: "ok",
          database: result?.ok === 1
        });
      } catch (error) {
        return Response.json(
          {
            status: "error",
            message: error.message
          },
          { status: 500 }
        );
      }
    }
 
    // API以外は従来どおりHTMLを表示
    return env.ASSETS.fetch(request);
  }
};
