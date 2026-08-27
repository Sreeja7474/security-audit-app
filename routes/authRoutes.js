const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const authMiddleware = require('../middleware/authMiddleware');
const { roleMiddleware, attributeMiddleware } = require('../middleware/roleMiddleware');

const router = express.Router();

// Register
router.post('/register', async (req, res) => {
  const { username, password, role, department } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword, role, department });
  await user.save();
  res.json({ message: "User registered" });
});

// Login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ message: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

  const token = jwt.sign(
    { id: user._id, role: user.role, department: user.department },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  res.json({ token });
});

// Protected route (RBAC)
router.get('/admin-data', authMiddleware, roleMiddleware('admin'), (req, res) => {
  res.json({ message: "Admin-only secure data" });
});

// Protected route (ABAC)
router.get('/audit-data', authMiddleware, attributeMiddleware('department', 'audit'), (req, res) => {
  res.json({ message: "Audit department secure data" });
});

module.exports = router;
