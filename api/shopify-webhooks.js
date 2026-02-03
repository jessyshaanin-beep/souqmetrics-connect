const crypto = require("crypto");

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.statusCode = 405;
    res.end("Method Not Allowed");
    return;
  }

  const hmac = req.headers["x-shopify-hmac-sha256"];
  if (!hmac) {
    res.statusCode = 401;
    res.end("Missing HMAC");
    return;
  }

  let body = "";
  req.on("data", chunk => {
    body += chunk.toString("utf8");
  });

  req.on("end", () => {
    const digest = crypto
      .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
      .update(body, "utf8")
      .digest("base64");

    if (digest.length !== hmac.length) {
      res.statusCode = 401;
      res.end("Invalid HMAC");
      return;
    }

    const valid = crypto.timingSafeEqual(
      Buffer.from(digest),
      Buffer.from(hmac)
    );

    if (!valid) {
      res.statusCode = 401;
      res.end("Invalid HMAC");
      return;
    }

    res.statusCode = 200;
    res.end("OK");
  });
};


