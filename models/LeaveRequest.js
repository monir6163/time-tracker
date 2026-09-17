const mongoose = require("mongoose");

const leaveRequestSchema = new mongoose.Schema(
  {
    teamCode: { type: String, required: true, index: true },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    reason: { type: String, required: true, trim: true, maxlength: 500 },
    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
    },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    reviewedAt: { type: Date },
  },
  { timestamps: true, versionKey: false },
);

module.exports = mongoose.model("LeaveRequest", leaveRequestSchema);
