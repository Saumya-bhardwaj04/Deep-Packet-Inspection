const jwt = require("jsonwebtoken");
const jwtSecret =
  process.env.JWT_SECRET ||
  (process.env.NODE_ENV !== "production" ? "dev-only-secret-change-me" : null);

module.exports = function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided" });
  }

  const token = authHeader.split(" ")[1];
  try {
    if (!jwtSecret) {
      return res.status(500).json({ error: "JWT secret is not configured" });
    }
    req.user = jwt.verify(token, jwtSecret);
    return next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
};
