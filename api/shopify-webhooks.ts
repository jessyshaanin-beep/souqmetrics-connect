export const config = {
  runtime: "nodejs",
};

import crypto from "crypto";

export default async function handler(req: any, res: any) {
  if (req.method !== "POST") {
    res.statusCode = 405;
    return res.end("Method Not Allowed");
  }

  const hmac = req.headers["x-shopify-hmac-sha256"];
  if (!hmac) {
    res.statusCode = 401;
    return res.end("Missing HMAC");
  }

  const rawBody = JSON.stringify(req.body ?? {});

  const digest = crypto
    .createHmac("sha256", process.env.SHOPIFY_API_SECRET!)
    .update(rawBody, "utf8")
    .digest("base64");

  if (digest.length !== hmac.length) {
    res.statusCode = 401;
    return res.end("Invalid HMAC");
  }

  const valid = crypto.timingSafeEqual(
    Buffer.from(digest),
    Buffer.from(hmac)
  );

  if (!valid) {
    res.statusCode = 401;
    return res.end("Invalid HMAC");
  }

  res.statusCode = 200;
  return res.end("OK");
}




