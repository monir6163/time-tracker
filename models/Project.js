const mongoose = require("mongoose");

const projectSchema = new mongoose.Schema(
  {
    teamCode: { type: String, required: true, index: true },
    name: { type: String, required: true, trim: true },
    description: { type: String, default: "", trim: true },
    status: { type: String, enum: ["active", "archived"], default: "active" },
    memberIds: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: true, versionKey: false },
);

projectSchema.index({ teamCode: 1, name: 1 }, { unique: true });

module.exports = mongoose.model("Project", projectSchema);
