const mongoose = require("mongoose");

const teamSchema = new mongoose.Schema(
  {
    teamCode: { type: String, required: true, unique: true, uppercase: true, trim: true },
    teamName: { type: String, required: true },
    admin: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

    // --- Screenshot privacy & scheduling settings (admin-configurable) ---
    screenshotIntervalMinutes: { type: Number, default: 10, enum: [5, 10, 15, 30] },

    // Idle time (seconds) after which auto-screenshot is skipped so we never
    // capture a personal screen while the person stepped away.
    idleThresholdSeconds: { type: Number, default: 60 },

    // Window-title keywords (case-insensitive substring match). If the
    // active/foreground window title contains any of these, the screenshot
    // is skipped entirely — never taken, never sent to the server.
    blockedKeywords: {
      type: [String],
      default: [
        "incognito",
        "inprivate",
        "private browsing",
        "password",
        "bitwarden",
        "1password",
        "lastpass",
        "keepass",
        "bank",
        "wallet",
        "whatsapp", // personal chat apps, opt-in removable by admin
      ],
    },
  },
  { timestamps: true, versionKey: false },
);

module.exports = mongoose.model("Team", teamSchema);
