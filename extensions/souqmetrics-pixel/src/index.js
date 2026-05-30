import { register } from "@shopify/web-pixels-extension";

register(({ analytics, browser }) => {
  const TRACK_URL = "https://frgzxxszpzclhnkgmkuw.supabase.co/functions/v1/track-funnel-event";

  function getStoreDomain(event) {
    const host = event.context?.document?.location?.host || "";
    return host.replace(/^www\./, "");
  }

  analytics.subscribe("product_added_to_cart", async (event) => {
    const item = event.data.cartLine?.merchandise?.product;
    await browser.sendBeacon(
      TRACK_URL,
      JSON.stringify({
        store_domain: getStoreDomain(event),
        event_type: "add_to_cart",
        session_id: event.id || "shopify",
        product_id: item?.id ? String(item.id).replace("gid://shopify/Product/", "") : null,
        product_name: item?.title || null
      })
    );
  });

  analytics.subscribe("checkout_started", async (event) => {
    await browser.sendBeacon(
      TRACK_URL,
      JSON.stringify({
        store_domain: getStoreDomain(event),
        event_type: "checkout",
        session_id: event.data?.checkout?.token || event.id || "shopify",
        product_id: null,
        product_name: null
      })
    );
  });

  analytics.subscribe("order_completed", async (event) => {
    await browser.sendBeacon(
      TRACK_URL,
      JSON.stringify({
        store_domain: getStoreDomain(event),
        event_type: "purchase",
        session_id: event.data?.checkout?.token || event.id || "shopify",
        product_id: null,
        product_name: null
      })
    );
  });

});
