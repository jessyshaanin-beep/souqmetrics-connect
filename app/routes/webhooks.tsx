import crypto from "crypto";

export const action = async ({ request }) => {
  const rawBody = await request.text();
  const hmac = request.headers.get("X-Shopify-Hmac-Sha256");

  if (!hmac) {
    return new Response("Missing HMAC", { status: 401 });
  }

  const digest = crypto
    .createHmac("sha256", process.env.SHOPIFY_API_SECRET!)
    .update(rawBody, "utf8")
    .digest("base64");

  const valid = crypto.timingSafeEqual(
    Buffer.from(digest),
    Buffer.from(hmac)
  );

  if (!valid) {
    return new Response("Invalid HMAC", { status: 401 });
  }

  return new Response("OK", { status: 200 });
};
