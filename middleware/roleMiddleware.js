function roleMiddleware(requiredRole) {
  return (req, res, next) => {
    if (req.user.role !== requiredRole) {
      return res.status(403).json({ message: "Access denied" });
    }
    next();
  };
}

function attributeMiddleware(attribute, value) {
  return (req, res, next) => {
    if (req.user[attribute] !== value) {
      return res.status(403).json({ message: "Access denied by attribute" });
    }
    next();
  };
}

module.exports = { roleMiddleware, attributeMiddleware };
