const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const authMiddleware = require("../middleware/auth");
const { requireAdmin } = require("../middleware/roles");
const {
  createUser,
  getUserByUsername,
  listUsers,
  updateUserRole,
  createAccessRequest,
  listPendingAccessRequests,
  getAccessRequestById,
  updateAccessRequestStatus,
  resolvePendingAccessRequestsForUser,
} = require("../config/store");

const router = express.Router();
const jwtSecret =
  process.env.JWT_SECRET ||
  (process.env.NODE_ENV !== "production" ? "dev-only-secret-change-me" : null);
const PRIMARY_ADMIN_USERNAME = String(process.env.PRIMARY_ADMIN_USERNAME || "samisharma000@gmail.com")
  .trim()
  .toLowerCase();

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function isStrongPassword(value) {
  const password = String(value || "");
  return (
    password.length >= 8 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}

function normalizeIdentity(value) {
  return String(value || "").trim().toLowerCase();
}

function ensurePrimaryAdminActor(actor) {
  if (normalizeIdentity(actor) !== PRIMARY_ADMIN_USERNAME) {
    return false;
  }
  return true;
}

router.post("/register", async (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  const role = "viewer";

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  if (!EMAIL_REGEX.test(username)) {
    return res.status(400).json({ error: "A valid email is required" });
  }

  if (!isStrongPassword(password)) {
    return res.status(400).json({
      error: "Password must be at least 8 chars and include uppercase, lowercase, number, and special character",
    });
  }

  try {
    const existing = await getUserByUsername(username);
    if (existing) {
      return res.status(400).json({ error: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await createUser({ username, password: hashedPassword, role });

    return res.json({
      message: "User created successfully",
      user,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.get("/users", authMiddleware, requireAdmin, async (req, res) => {
  try {
    const users = await listUsers();
    return res.json(users);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.post("/request-access", authMiddleware, async (req, res) => {
  const username = String(req.user?.username || "").trim();
  const role = String(req.user?.role || "viewer");

  if (!username) {
    return res.status(400).json({ error: "Invalid user" });
  }

  if (role === "admin") {
    return res.status(400).json({ error: "Admin account does not require access request" });
  }

  try {
    const request = await createAccessRequest(username);
    return res.json({
      message: "Request sent to admin",
      request,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.get("/access-requests", authMiddleware, requireAdmin, async (req, res) => {
  try {
    const requests = await listPendingAccessRequests();
    return res.json(requests);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.patch("/access-requests/:id/approve", authMiddleware, requireAdmin, async (req, res) => {
  const requestId = String(req.params.id || "").trim();
  const reviewer = String(req.user?.username || "").trim();
  if (!ensurePrimaryAdminActor(reviewer)) {
    return res.status(403).json({ error: "Only primary admin can approve access requests" });
  }
  if (!requestId) {
    return res.status(400).json({ error: "Request id is required" });
  }

  try {
    const request = await getAccessRequestById(requestId);
    if (!request) {
      return res.status(404).json({ error: "Access request not found" });
    }
    if (request.status !== "pending") {
      return res.status(400).json({ error: "Only pending requests can be approved" });
    }

    const target = await getUserByUsername(request.username);
    if (!target) {
      return res.status(404).json({ error: "Requested user does not exist" });
    }

    await updateUserRole(request.username, "admin");
    await updateAccessRequestStatus(requestId, "approved", reviewer);
    await resolvePendingAccessRequestsForUser(request.username, "approved", reviewer);
    return res.json({ message: `${request.username} promoted to admin` });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.patch("/access-requests/:id/reject", authMiddleware, requireAdmin, async (req, res) => {
  const requestId = String(req.params.id || "").trim();
  const reviewer = String(req.user?.username || "").trim();
  if (!ensurePrimaryAdminActor(reviewer)) {
    return res.status(403).json({ error: "Only primary admin can reject access requests" });
  }
  if (!requestId) {
    return res.status(400).json({ error: "Request id is required" });
  }

  try {
    const request = await getAccessRequestById(requestId);
    if (!request) {
      return res.status(404).json({ error: "Access request not found" });
    }
    if (request.status !== "pending") {
      return res.status(400).json({ error: "Only pending requests can be rejected" });
    }

    await updateAccessRequestStatus(requestId, "rejected", reviewer);
    await resolvePendingAccessRequestsForUser(request.username, "rejected", reviewer);
    return res.json({ message: `${request.username} request rejected` });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.patch("/promote/:username", authMiddleware, requireAdmin, async (req, res) => {
  const username = String(req.params.username || "").trim();
  const actor = String(req.user?.username || "").trim();
  if (!ensurePrimaryAdminActor(actor)) {
    return res.status(403).json({ error: "Only primary admin can promote users" });
  }
  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }

  try {
    const target = await getUserByUsername(username);
    if (!target) {
      return res.status(404).json({ error: "User not found" });
    }
    if (target.role === "admin") {
      return res.json({ message: `${username} is already an admin` });
    }

    await updateUserRole(username, "admin");
    await resolvePendingAccessRequestsForUser(username, "approved", actor);
    return res.json({ message: `${username} promoted to admin` });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.patch("/demote/:username", authMiddleware, requireAdmin, async (req, res) => {
  const username = String(req.params.username || "").trim();
  const actor = String(req.user?.username || "").trim();
  if (!ensurePrimaryAdminActor(actor)) {
    return res.status(403).json({ error: "Only primary admin can demote users" });
  }
  const usernameNorm = username.toLowerCase();
  const actorNorm = actor.toLowerCase();
  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }

  if (usernameNorm === actorNorm) {
    return res.status(400).json({ error: "You cannot demote yourself" });
  }

  if (usernameNorm === PRIMARY_ADMIN_USERNAME && actorNorm !== PRIMARY_ADMIN_USERNAME) {
    return res.status(403).json({ error: "Primary admin cannot be demoted" });
  }

  try {
    const target = await getUserByUsername(username);
    if (!target) {
      return res.status(404).json({ error: "User not found" });
    }
    if (target.role !== "admin") {
      return res.status(400).json({ error: "User is not an admin" });
    }

    await updateUserRole(username, "viewer");
    await resolvePendingAccessRequestsForUser(username, "rejected", actor);
    return res.json({ message: `${username} demoted to viewer` });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  try {
    if (!jwtSecret) {
      return res.status(500).json({ error: "JWT secret is not configured" });
    }

    const user = await getUserByUsername(username);
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { username: user.username, role: user.role, id: user.id },
      jwtSecret,
      { expiresIn: "24h" }
    );

    return res.json({ token, username: user.username, role: user.role });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

module.exports = router;
