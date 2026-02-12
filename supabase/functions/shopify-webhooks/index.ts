import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createHmac } from "https://deno.land/std@0.168.0/node/crypto.ts";

serve(async (req) => {
  if (req.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const secret = Deno.env.get("SHOPIFY_API_SECRET");
  if (!secret) {
    return new Response("Missing server secret", { status: 500 });
  }

  const hmac = req.headers.get("x-shopify-hmac-sha256");
  if (!hmac) {
    return new Response("Missing HMAC", { status: 401 });
  }

  const rawBody = await req.text();

  const digest = createHmac("sha256", secret)
    .update(rawBody, "utf8")
    .digest("base64");

  // Constant-time comparison
  if (digest.length !== hmac.length) {
    return new Response("Invalid HMAC", { status: 401 });
  }

  let valid = true;
  for (let i = 0; i < digest.length; i++) {
    if (digest.charCodeAt(i) !== hmac.charCodeAt(i)) {
      valid = false;
    }
  }

  if (!valid) {
    return new Response("Invalid HMAC", { status: 401 });
  }

  return new Response("OK", { status: 200 });
});


