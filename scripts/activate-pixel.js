const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

async function run() {
  const sessions = await prisma.session.findMany({
    where: { isOnline: false }
  });

  for (const session of sessions) {
    console.log("Activating pixel for", session.shop);
    const res = await fetch(`https://${session.shop}/admin/api/2024-01/graphql.json`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": session.accessToken,
      },
      body: JSON.stringify({
        query: `mutation { webPixelCreate(webPixel: { settings: "{}" }) { webPixel { id } userErrors { field message } } }`
      })
    });
    const data = await res.json();
    console.log(JSON.stringify(data));
  }
  await prisma.$disconnect();
}

run();
