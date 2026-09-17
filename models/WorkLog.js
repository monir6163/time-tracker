const mongoose = require("mongoose");

const workLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    teamCode: { type: String, required: true },
    projectId: { type: mongoose.Schema.Types.ObjectId, ref: "Project" },
    startTime: { type: Date, required: true },
    endTime: { type: Date },
    totalSeconds: { type: Number, default: 0 },
    approvalStatus: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
    },
    approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    approvedAt: { type: Date },
    screenshots: [
      {
        fileName: String, // resolved to bytes only via the authenticated /api/admin/screenshot-file route
        timestamp: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true, versionKey: false },
);

module.exports = mongoose.model("WorkLog", workLogSchema);
