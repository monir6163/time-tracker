module.exports = function (req, res, next) {
  if (!req.user || req.user.role !== "super_admin") {
    return res
      .status(403)
      .json({ success: false, message: "Access denied. Super Admin only." });
  }
  next();
};
