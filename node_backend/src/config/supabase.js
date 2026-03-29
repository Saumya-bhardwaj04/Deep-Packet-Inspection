const { createClient } = require("@supabase/supabase-js");

let cachedClient = null;

function getSupabaseClient() {
  if (cachedClient) {
    return cachedClient;
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;

  if (!url || !key) {
    throw new Error("Supabase is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in node_backend/.env");
  }

  cachedClient = createClient(url, key);
  return cachedClient;
}

module.exports = { getSupabaseClient };
