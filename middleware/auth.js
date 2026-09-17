const jwt = require("jsonwebtoken");
const User = require("../models/User");

module.exports = async function (req, res, next) {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res
      .status(401)
      .json({ success: false, message: "Access denied. No token provided." });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(verified.userId).select(
      "status role teamCode",
    );
    if (!user || user.status !== "active") {
      return res
        .status(403)
        .json({ success: false, message: "This account is inactive." });
    }
    req.user = {
      ...verified,
      role: user.role,
      teamCode: user.teamCode,
    };
    next();
  } catch (err) {
    res.status(400).json({ success: false, message: "Invalid token." });
  }
};
