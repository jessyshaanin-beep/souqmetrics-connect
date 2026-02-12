import crypto from "crypto";

export const config = {
  api: {
    bodyParser: false,
  },
};

export default function handler(req: any, res: any) {
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

  const chunks: Buffer[] = [];

  req.on("data", (chunk: Buffer) => {
    chunks.push(chunk);
  });

  req.on("end", () => {
    const rawBody = Buffer.concat(chunks).toString("utf8");

    const digest = crypto
      .createHmac("sha256", process.env.SHOPIFY_API_SECRET!)
      .update(rawBody, "utf8")
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
}


