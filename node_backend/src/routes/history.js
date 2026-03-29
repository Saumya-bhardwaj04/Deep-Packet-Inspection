const express = require("express");
const authMiddleware = require("../middleware/auth");
const { requireAdmin } = require("../middleware/roles");
const { getRuns, getAllRuns, deleteRun } = require("../config/store");

const router = express.Router();

router.get("/", authMiddleware, async (req, res) => {
  try {
    const runs = req.user?.role === "admin" ? await getAllRuns(50) : await getRuns(req.user.username, 20);
    return res.json(runs);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.delete("/:id", authMiddleware, requireAdmin, async (req, res) => {
  try {
    await deleteRun(req.params.id, req.user.username);
    return res.json({ message: "Deleted successfully" });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

module.exports = router;
