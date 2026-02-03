import crypto from "crypto";
import { IncomingMessage, ServerResponse } from "http";

export const config = {
  api: {
    bodyParser: false,
  },
};

export default async function handler(
  req: IncomingMessage & { body?: any },
  res: ServerResponse
) {
  const chunks: Buffer[] = [];

  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    const rawBody = Buffer.concat(chunks).toString("utf8");
    const hmac = req.headers["x-shopify-hmac-sha256"] as string;

    if (!hmac) {
      res.statusCode = 401;
      res.end("Missing HMAC");
      return;
    }

    const digest = crypto
      .createHmac("sha256", process.env.SHOPIFY_API_SECRET!)
      .update(rawBody)
      .digest("base64");

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
}
