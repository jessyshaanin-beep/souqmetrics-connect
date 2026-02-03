import crypto from "crypto";

export const runtime = "nodejs";

export const action = async ({ request }) => {
  const secret = process.env.SHOPIFY_API_SECRET;

  if (!secret) {
    return new Response("Missing secret", { status: 500 });
  }

  const hmac = request.headers.get("x-shopify-hmac-sha256");

  if (!hmac) {
    return new Response("Missing HMAC", { status: 401 });
  }

  const rawBody = await request.text();

  const digest = crypto
    .createHmac("sha256", secret)
    .update(rawBody, "utf8")
    .digest("base64");

  if (digest.length !== hmac.length) {
    return new Response("Invalid HMAC", { status: 401 });
  }

  const valid = crypto.timingSafeEqual(
    Buffer.from(digest),
    Buffer.from(hmac)
  );

  if (!valid) {
    return new Response("Invalid HMAC", { status: 401 });
  }

  return new Response("OK", { status: 200 });
};



