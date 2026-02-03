export const config = {
  runtime: "nodejs",
};

import crypto from "crypto";
import type { VercelRequest, VercelResponse } from "@vercel/node";

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  const hmac = req.headers["x-shopify-hmac-sha256"] as string;
  if (!hmac) {
    return res.status(401).send("Missing HMAC");
  }

  const rawBody = JSON.stringify(req.body);

  const digest = crypto
    .createHmac("sha256", process.env.SHOPIFY_API_SECRET as string)
    .update(rawBody, "utf8")
    .digest("base64");

  const valid = crypto.timingSafeEqual(
    Buffer.from(digest),
    Buffer.from(hmac)
  );

  if (!valid) {
    return res.status(401).send("Invalid HMAC");
  }

  return res.status(200).send("OK");
}
