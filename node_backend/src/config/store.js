const { getSupabaseClient } = require("./supabase");

function nowIso() {
  return new Date().toISOString();
}

async function getUserByUsername(username) {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase
    .from("users")
    .select("*")
    .eq("username", username)
    .maybeSingle();
  if (error) {
    throw error;
  }
  return data || null;
}

async function createUser({ username, password, role }) {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase
    .from("users")
    .insert([{ username, password, role }])
    .select("id,username,role,created_at")
    .single();
  if (error) {
    throw error;
  }
  return data;
}

async function listUsers() {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase
    .from("users")
    .select("id,username,role,created_at")
    .order("created_at", { ascending: false });
  if (error) {
    throw error;
  }
  return data || [];
}

async function updateUserRole(username, role) {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase
    .from("users")
    .update({ role })
    .eq("username", username)
    .select("id,username,role,created_at")
    .maybeSingle();
  if (error) {
    throw error;
  }
  return data || null;
}

async function upsertRules(userId, rules) {
  const supabase = getSupabaseClient();
  const existing = await supabase
    .from("rules")
    .select("id")
    .eq("user_id", userId)
    .maybeSingle();

  if (existing.error) {
    throw existing.error;
  }

  if (existing.data) {
    const { error } = await supabase
      .from("rules")
      .update({ ...rules })
      .eq("user_id", userId);
    if (error) {
      throw error;
    }
    return;
  }

  const { error } = await supabase
    .from("rules")
    .insert([{ user_id: userId, ...rules }]);
  if (error) {
    throw error;
  }
}

async function getRules(userId) {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase
    .from("rules")
    .select("*")
    .eq("user_id", userId)
    .maybeSingle();
  if (error) {
    throw error;
  }
  return data || null;
}

async function addRun(run) {
  const supabase = getSupabaseClient();
  const { error } = await supabase.from("dpi_runs").insert([run]);
  if (error) {
    throw error;
  }
}

async function getRuns(userId, limit = 20) {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase
    .from("dpi_runs")
    .select("*")
    .eq("user_id", userId)
    .order("timestamp", { ascending: false })
    .limit(limit);
  if (error) {
    throw error;
  }
  return data || [];
}

async function getAllRuns(limit = 50) {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase
    .from("dpi_runs")
    .select("*")
    .order("timestamp", { ascending: false })
    .limit(limit);
  if (error) {
    throw error;
  }
  return data || [];
}

async function getRunById(runId) {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase
    .from("dpi_runs")
    .select("*")
    .eq("id", runId)
    .maybeSingle();
  if (error) {
    throw error;
  }
  return data || null;
}

async function deleteRun(runId, userId) {
  const supabase = getSupabaseClient();
  const { error } = await supabase
    .from("dpi_runs")
    .delete()
    .eq("id", runId)
    .eq("user_id", userId);
  if (error) {
    throw error;
  }
}

async function createAccessRequest(username) {
  const supabase = getSupabaseClient();
  const existing = await supabase
    .from("access_requests")
    .select("id,username,status,requested_at")
    .eq("username", username)
    .eq("status", "pending")
    .maybeSingle();

  if (existing.error) {
    throw existing.error;
  }

  if (existing.data) {
    return existing.data;
  }

  const { data, error } = await supabase
    .from("access_requests")
    .insert([{ username, status: "pending", requested_at: nowIso() }])
    .select("id,username,status,requested_at")
    .single();

  if (error) {
    throw error;
  }
  return data;
}

async function listPendingAccessRequests() {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase
    .from("access_requests")
    .select("id,username,status,requested_at,reviewed_at,reviewed_by")
    .eq("status", "pending")
    .order("requested_at", { ascending: false });
  if (error) {
    throw error;
  }
  return data || [];
}

async function getAccessRequestById(requestId) {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase
    .from("access_requests")
    .select("id,username,status,requested_at,reviewed_at,reviewed_by")
    .eq("id", requestId)
    .maybeSingle();
  if (error) {
    throw error;
  }
  return data || null;
}

async function updateAccessRequestStatus(requestId, status, reviewedBy) {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase
    .from("access_requests")
    .update({ status, reviewed_at: nowIso(), reviewed_by: reviewedBy })
    .eq("id", requestId)
    .select("id,username,status,requested_at,reviewed_at,reviewed_by")
    .maybeSingle();
  if (error) {
    throw error;
  }
  return data || null;
}

async function resolvePendingAccessRequestsForUser(username, status, reviewedBy) {
  const supabase = getSupabaseClient();
  const safeUsername = String(username || "").trim();
  if (!safeUsername) {
    return [];
  }

  const { data, error } = await supabase
    .from("access_requests")
    .update({ status, reviewed_at: nowIso(), reviewed_by: reviewedBy })
    .eq("username", safeUsername)
    .eq("status", "pending")
    .select("id,username,status,requested_at,reviewed_at,reviewed_by");

  if (error) {
    throw error;
  }

  return data || [];
}

module.exports = {
  getUserByUsername,
  createUser,
  listUsers,
  updateUserRole,
  createAccessRequest,
  listPendingAccessRequests,
  getAccessRequestById,
  updateAccessRequestStatus,
  resolvePendingAccessRequestsForUser,
  upsertRules,
  getRules,
  addRun,
  getRuns,
  getAllRuns,
  getRunById,
  deleteRun,
};
