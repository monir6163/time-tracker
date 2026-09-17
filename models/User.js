const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: { type: String, required: true },
    role: {
      type: String,
      enum: ["super_admin", "admin", "member"],
      default: "member",
    },
    teamCode: { type: String, required: true, uppercase: true, trim: true },
    status: {
      type: String,
      enum: ["active", "inactive", "invited"],
      default: "active",
    },
    lastActiveAt: { type: Date },
    passwordResetTokenHash: { type: String, select: false },
    passwordResetExpiresAt: { type: Date, select: false },
  },
  { timestamps: true, versionKey: false },
);

module.exports = mongoose.model("User", userSchema);
