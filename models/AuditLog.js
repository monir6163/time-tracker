const mongoose = require("mongoose");

const auditLogSchema = new mongoose.Schema(
  {
    teamCode: { type: String, required: true, index: true },
    actorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    action: { type: String, required: true },
    entityType: { type: String, required: true },
    entityId: { type: mongoose.Schema.Types.ObjectId },
    details: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { timestamps: true, versionKey: false },
);

module.exports = mongoose.model("AuditLog", auditLogSchema);
