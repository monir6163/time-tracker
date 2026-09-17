const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const User = require("./models/User");
const Team = require("./models/Team");
const WorkLog = require("./models/WorkLog");
const Project = require("./models/Project");
const LeaveRequest = require("./models/LeaveRequest");
const AuditLog = require("./models/AuditLog");
const authMiddleware = require("./middleware/auth");
const adminAuth = require("./middleware/adminAuth");
const superAdminAuth = require("./middleware/superAdminAuth");
const {
  sendInviteEmail,
  sendNotificationEmail,
  sendPasswordResetEmail,
} = require("./utils/mailer");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be at least 32 characters long");
}
if (
  !process.env.SUPER_ADMIN_BOOTSTRAP_KEY ||
  process.env.SUPER_ADMIN_BOOTSTRAP_KEY.length < 16
) {
  throw new Error("SUPER_ADMIN_BOOTSTRAP_KEY must be configured securely");
}

// Middlewares
const allowedOrigins = (process.env.CORS_ORIGINS || "http://localhost:5173")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
app.use(cors({ origin: allowedOrigins }));
app.use(express.json({ limit: "20mb" }));

// NOTE: screenshots are intentionally NOT served via express.static anymore.
// A public /uploads folder means anyone who finds/guesses a filename can
// view any team's screenshots with no login at all. All screenshot access
// now goes through the authenticated /api/admin/screenshot-file route below.

const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected Successfully"))
  .catch((err) => console.error("MongoDB Error:", err));

function genTeamCode() {
  return crypto.randomBytes(4).toString("hex").toUpperCase(); // e.g. "A1B2C3D4"
}

function signUser(user) {
  return jwt.sign(
    { userId: user._id, role: user.role, teamCode: user.teamCode },
    JWT_SECRET,
    { expiresIn: "7d" },
  );
}

async function writeAudit({
  teamCode,
  actorId,
  action,
  entityType,
  entityId,
  details = {},
}) {
  return AuditLog.create({
    teamCode,
    actorId,
    action,
    entityType,
    entityId,
    details,
  });
}

function csvCell(value) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

// =====================================================================
// TEAM CREATION (admin signs up and creates a brand new team)
// =====================================================================
app.post("/api/team/register", async (req, res) => {
  try {
    const { name, email, password, teamName } = req.body;
    if (!name || !email || !password || !teamName) {
      return res
        .status(400)
        .json({ success: false, message: "All fields are required" });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res
        .status(400)
        .json({ success: false, message: "User already exists" });
    }

    let teamCode = genTeamCode();
    // extremely unlikely collision, but guard anyway
    while (await Team.findOne({ teamCode })) teamCode = genTeamCode();

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const adminUser = new User({
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      role: "admin",
      teamCode,
    });
    await adminUser.save();

    const team = new Team({ teamCode, teamName, admin: adminUser._id });
    await team.save();

    res.status(201).json({
      success: true,
      message: "Team created",
      teamCode,
      token: signUser(adminUser),
      user: {
        id: adminUser._id,
        name: adminUser.name,
        role: adminUser.role,
        teamCode,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// =====================================================================
// JOIN EXISTING TEAM (member registration — via team code or email invite)
// =====================================================================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, inviteToken } = req.body;
    let { teamCode } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "All fields are required" });
    }

    let invitedEmail = null;
    if (inviteToken) {
      try {
        const decoded = jwt.verify(inviteToken, JWT_SECRET);
        if (decoded.type !== "invite") throw new Error("bad token");
        teamCode = decoded.teamCode;
        invitedEmail = decoded.email.toLowerCase();
      } catch {
        return res.status(400).json({
          success: false,
          message: "Invite link is invalid or expired",
        });
      }
      if (invitedEmail !== email.toLowerCase()) {
        return res.status(400).json({
          success: false,
          message: "This invite was sent to a different email address",
        });
      }
    }

    if (!teamCode) {
      return res
        .status(400)
        .json({ success: false, message: "Team code is required" });
    }
    teamCode = teamCode.toUpperCase().trim();

    const team = await Team.findOne({ teamCode });
    if (!team) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid team code" });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res
        .status(400)
        .json({ success: false, message: "User already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Role is ALWAYS "member" here, regardless of what the client sends —
    // this closes the old hole where anyone could self-register as admin
    // of someone else's team just by knowing the team code.
    const newUser = new User({
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      role: "member",
      teamCode,
    });
    await newUser.save();

    res.status(201).json({ success: true, message: "Registration successful" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// =====================================================================
// LOGIN
// =====================================================================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: (email || "").toLowerCase() });
    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid credentials" });
    }

    if (user.status !== "active") {
      return res.status(403).json({
        success: false,
        message: "This account is inactive. Contact your admin.",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid credentials" });
    }

    res.json({
      success: true,
      token: signUser(user),
      user: {
        id: user._id,
        name: user.name,
        role: user.role,
        teamCode: user.teamCode,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select(
      "name email role teamCode status",
    );
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        teamCode: user.teamCode,
        status: user.status,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Unable to load account" });
  }
});

app.post("/api/super-admin/bootstrap", async (req, res) => {
  try {
    const bootstrapKey = req.header("x-super-admin-key");
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    if (
      !process.env.SUPER_ADMIN_BOOTSTRAP_KEY ||
      bootstrapKey !== process.env.SUPER_ADMIN_BOOTSTRAP_KEY
    ) {
      return res
        .status(403)
        .json({ success: false, message: "Invalid bootstrap credentials" });
    }
    if (await User.exists({ role: "super_admin" })) {
      return res
        .status(409)
        .json({ success: false, message: "Super Admin is already configured" });
    }
    const user = await User.findOne({ email, status: "active" });
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "Active user not found" });
    user.role = "super_admin";
    await user.save();
    await writeAudit({
      teamCode: user.teamCode,
      actorId: user._id,
      action: "role.super_admin_granted",
      entityType: "User",
      entityId: user._id,
    });
    res.json({
      success: true,
      message:
        "Super Admin access granted. Log in again to refresh your token.",
    });
  } catch (err) {
    res
      .status(500)
      .json({ success: false, message: "Unable to grant Super Admin access" });
  }
});

app.get(
  "/api/super-admin/overview",
  authMiddleware,
  superAdminAuth,
  async (req, res) => {
    try {
      const [teams, users] = await Promise.all([
        Team.find()
          .populate("admin", "name email role")
          .sort({ createdAt: -1 }),
        User.find()
          .select("name email role teamCode status lastActiveAt createdAt")
          .sort({ createdAt: -1 }),
      ]);
      const teamRows = await Promise.all(
        teams.map(async (team) => ({
          id: team._id,
          teamCode: team.teamCode,
          teamName: team.teamName,
          admin: team.admin,
          memberCount: await User.countDocuments({ teamCode: team.teamCode }),
          createdAt: team.createdAt,
        })),
      );
      res.json({
        success: true,
        totals: { teams: teams.length, users: users.length },
        teams: teamRows,
        users,
      });
    } catch (err) {
      res.status(500).json({
        success: false,
        message: "Unable to load Super Admin overview",
      });
    }
  },
);

app.patch(
  "/api/super-admin/users/:userId",
  authMiddleware,
  superAdminAuth,
  async (req, res) => {
    try {
      const { role, status } = req.body;
      if (role !== undefined && !["admin", "member"].includes(role))
        return res
          .status(400)
          .json({ success: false, message: "Role must be admin or member" });
      if (status !== undefined && !["active", "inactive"].includes(status))
        return res.status(400).json({
          success: false,
          message: "Status must be active or inactive",
        });
      if (req.params.userId === req.user.userId && status === "inactive")
        return res
          .status(400)
          .json({ success: false, message: "You cannot deactivate yourself" });
      const user = await User.findById(req.params.userId);
      if (!user || user.role === "super_admin")
        return res
          .status(404)
          .json({ success: false, message: "Managed user not found" });
      if (role !== undefined) user.role = role;
      if (status !== undefined) user.status = status;
      await user.save();
      await writeAudit({
        teamCode: user.teamCode,
        actorId: req.user.userId,
        action: "super_admin.user_updated",
        entityType: "User",
        entityId: user._id,
        details: { role: user.role, status: user.status },
      });
      res.json({
        success: true,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          teamCode: user.teamCode,
          status: user.status,
        },
      });
    } catch (err) {
      res
        .status(500)
        .json({ success: false, message: "Unable to update user" });
    }
  },
);

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    const genericResponse = {
      success: true,
      message: "If an account exists, a password reset link has been sent.",
    };
    if (!email) return res.json(genericResponse);

    const user = await User.findOne({ email }).select(
      "+passwordResetTokenHash +passwordResetExpiresAt",
    );
    if (!user || user.status !== "active") return res.json(genericResponse);

    const resetToken = crypto.randomBytes(32).toString("hex");
    user.passwordResetTokenHash = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");
    user.passwordResetExpiresAt = new Date(Date.now() + 30 * 60 * 1000);
    await user.save();

    const resetLink = `${process.env.APP_RESET_URL || "http://localhost:5173"}?resetToken=${resetToken}`;
    await sendPasswordResetEmail({ to: user.email, resetLink });
    res.json(genericResponse);
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Unable to process password reset request",
    });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || typeof password !== "string" || password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Token and a password of at least 8 characters are required",
      });
    }
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
      passwordResetTokenHash: tokenHash,
      passwordResetExpiresAt: { $gt: new Date() },
      status: "active",
    }).select("+passwordResetTokenHash +passwordResetExpiresAt");
    if (!user)
      return res
        .status(400)
        .json({ success: false, message: "Reset link is invalid or expired" });

    user.password = await bcrypt.hash(password, await bcrypt.genSalt(10));
    user.passwordResetTokenHash = undefined;
    user.passwordResetExpiresAt = undefined;
    await user.save();
    await writeAudit({
      teamCode: user.teamCode,
      actorId: user._id,
      action: "password.reset",
      entityType: "User",
      entityId: user._id,
    });
    res.json({
      success: true,
      message: "Password reset successfully. You can now log in.",
    });
  } catch (err) {
    res
      .status(500)
      .json({ success: false, message: "Unable to reset password" });
  }
});

app.patch("/api/auth/change-password", authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (
      !currentPassword ||
      typeof newPassword !== "string" ||
      newPassword.length < 8
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Current password and a new password of at least 8 characters are required",
      });
    }
    const user = await User.findById(req.user.userId);
    if (!user || !(await bcrypt.compare(currentPassword, user.password))) {
      return res
        .status(400)
        .json({ success: false, message: "Current password is incorrect" });
    }
    user.password = await bcrypt.hash(newPassword, await bcrypt.genSalt(10));
    user.passwordResetTokenHash = undefined;
    user.passwordResetExpiresAt = undefined;
    await user.save();
    await writeAudit({
      teamCode: user.teamCode,
      actorId: user._id,
      action: "password.changed",
      entityType: "User",
      entityId: user._id,
    });
    res.json({ success: true, message: "Password changed successfully" });
  } catch (err) {
    res
      .status(500)
      .json({ success: false, message: "Unable to change password" });
  }
});

// =====================================================================
// ADMIN: INVITE A TEAMMATE BY EMAIL
// =====================================================================
app.post("/api/admin/invite", authMiddleware, adminAuth, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res
        .status(400)
        .json({ success: false, message: "Email is required" });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "That person already has an account",
      });
    }

    const team = await Team.findOne({ teamCode: req.user.teamCode });
    const admin = await User.findById(req.user.userId);

    const inviteToken = jwt.sign(
      {
        type: "invite",
        teamCode: req.user.teamCode,
        email: email.toLowerCase(),
      },
      JWT_SECRET,
      { expiresIn: "7d" },
    );

    const inviteLink = `${process.env.APP_JOIN_URL || "https://your-app-domain.example/join"}?token=${inviteToken}`;

    const { sent } = await sendInviteEmail({
      to: email,
      teamName: team?.teamName || req.user.teamCode,
      inviteLink,
      inviterName: admin?.name || "Your admin",
    });

    res.json({
      success: true,
      emailSent: sent,
      inviteLink, // returned always so the admin can share it manually (WhatsApp/SMS) if SMTP isn't configured
      teamCode: req.user.teamCode,
      message: sent
        ? "Invite emailed successfully"
        : "Email isn't configured on the server — share this invite link manually",
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/api/admin/members", authMiddleware, adminAuth, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    const password = String(req.body.password || "");
    if (!name || !email || password.length < 8) {
      return res.status(400).json({
        success: false,
        message:
          "Name, email and a password of at least 8 characters are required",
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res
        .status(409)
        .json({ success: false, message: "That email already has an account" });

    const member = await User.create({
      name,
      email,
      password: await bcrypt.hash(password, await bcrypt.genSalt(10)),
      role: "member",
      status: "active",
      teamCode: req.user.teamCode,
    });
    await writeAudit({
      teamCode: req.user.teamCode,
      actorId: req.user.userId,
      action: "member.created",
      entityType: "User",
      entityId: member._id,
      details: { email: member.email },
    });

    res.status(201).json({
      success: true,
      message: "Team member added. Share the temporary password securely.",
      member: {
        id: member._id,
        name: member.name,
        email: member.email,
        role: member.role,
        status: member.status,
      },
    });
  } catch (err) {
    res
      .status(500)
      .json({ success: false, message: "Unable to add team member" });
  }
});

// =====================================================================
// TEAM SETTINGS — readable by any logged-in team member (needed so the
// desktop tracker knows the current screenshot interval + privacy blocklist)
// =====================================================================
app.get("/api/team/settings", authMiddleware, async (req, res) => {
  try {
    const team = await Team.findOne({ teamCode: req.user.teamCode });
    if (!team)
      return res
        .status(404)
        .json({ success: false, message: "Team not found" });

    res.json({
      success: true,
      screenshotIntervalMinutes: team.screenshotIntervalMinutes,
      idleThresholdSeconds: team.idleThresholdSeconds,
      blockedKeywords: team.blockedKeywords,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// =====================================================================
// ADMIN: UPDATE SETTINGS (screenshot interval + privacy blocklist)
// =====================================================================
app.patch(
  "/api/admin/settings",
  authMiddleware,
  adminAuth,
  async (req, res) => {
    try {
      const {
        screenshotIntervalMinutes,
        idleThresholdSeconds,
        blockedKeywords,
      } = req.body;
      const update = {};

      if (screenshotIntervalMinutes !== undefined) {
        if (![5, 10, 15, 30].includes(Number(screenshotIntervalMinutes))) {
          return res.status(400).json({
            success: false,
            message: "Interval must be 5, 10, 15 or 30 minutes",
          });
        }
        update.screenshotIntervalMinutes = Number(screenshotIntervalMinutes);
      }
      if (idleThresholdSeconds !== undefined) {
        update.idleThresholdSeconds = Math.max(
          30,
          Math.min(600, Number(idleThresholdSeconds)),
        );
      }
      if (Array.isArray(blockedKeywords)) {
        update.blockedKeywords = blockedKeywords
          .map((k) => String(k).trim().toLowerCase())
          .filter(Boolean)
          .slice(0, 50);
      }

      const team = await Team.findOneAndUpdate(
        { teamCode: req.user.teamCode },
        { $set: update },
        { new: true },
      );
      if (!team)
        return res
          .status(404)
          .json({ success: false, message: "Team not found" });

      res.json({ success: true, settings: team });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  },
);

// =====================================================================
// TRACKING: START / SCREENSHOT / STOP
// =====================================================================
app.post("/api/track/start", authMiddleware, async (req, res) => {
  try {
    const { projectId } = req.body;
    // guard against duplicate concurrent sessions for the same user
    const openSession = await WorkLog.findOne({
      userId: req.user.userId,
      endTime: null,
    });
    if (openSession) {
      return res.json({
        success: true,
        sessionId: openSession._id,
        resumed: true,
      });
    }

    let project = null;
    if (projectId) {
      project = await Project.findOne({
        _id: projectId,
        teamCode: req.user.teamCode,
        status: "active",
        memberIds: req.user.userId,
      });
      if (!project)
        return res
          .status(400)
          .json({ success: false, message: "Project is not assigned to you" });
    }

    const newSession = new WorkLog({
      userId: req.user.userId,
      teamCode: req.user.teamCode,
      projectId: project?._id,
      startTime: new Date(),
    });
    const savedSession = await newSession.save();
    await User.findByIdAndUpdate(req.user.userId, { lastActiveAt: new Date() });
    res.json({ success: true, sessionId: savedSession._id });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/api/track/screenshot", authMiddleware, async (req, res) => {
  try {
    const { sessionId, imageBase64, totalSeconds } = req.body;
    if (!sessionId || !imageBase64) {
      return res
        .status(400)
        .json({ success: false, message: "Missing parameters" });
    }

    // Ownership check — without this, any logged-in user could push
    // screenshots into someone else's session by guessing a sessionId.
    const session = await WorkLog.findById(sessionId);
    if (!session || session.userId.toString() !== req.user.userId) {
      return res
        .status(403)
        .json({ success: false, message: "Not your session" });
    }

    if (!/^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(imageBase64)) {
      return res
        .status(400)
        .json({ success: false, message: "Only PNG screenshots are accepted" });
    }
    const base64Data = imageBase64.replace(/^data:image\/png;base64,/, "");
    const fileName = `scr_${req.user.userId}_${Date.now()}.png`;
    const filePath = path.join(uploadDir, fileName);
    fs.writeFileSync(filePath, base64Data, "base64");

    await WorkLog.findByIdAndUpdate(sessionId, {
      totalSeconds,
      $push: { screenshots: { fileName, timestamp: new Date() } },
    });
    await User.findByIdAndUpdate(req.user.userId, { lastActiveAt: new Date() });

    res.json({ success: true, message: "Screenshot and log synced" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/api/track/stop", authMiddleware, async (req, res) => {
  try {
    const { sessionId, totalSeconds } = req.body;

    const session = await WorkLog.findById(sessionId);
    if (!session || session.userId.toString() !== req.user.userId) {
      return res
        .status(403)
        .json({ success: false, message: "Not your session" });
    }

    await WorkLog.findByIdAndUpdate(sessionId, {
      endTime: new Date(),
      totalSeconds,
    });
    res.json({ success: true, message: "Session stopped successfully" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Members can see only projects assigned to them; admins see every active project.
app.get("/api/projects", authMiddleware, async (req, res) => {
  try {
    const filter = { teamCode: req.user.teamCode, status: "active" };
    if (req.user.role !== "admin") filter.memberIds = req.user.userId;
    const projects = await Project.find(filter)
      .select("name description memberIds status")
      .sort({ name: 1 });
    res.json({ success: true, projects });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/api/admin/projects", authMiddleware, adminAuth, async (req, res) => {
  try {
    const { name, description = "", memberIds = [] } = req.body;
    if (!name?.trim())
      return res
        .status(400)
        .json({ success: false, message: "Project name is required" });
    const validMembers = await User.find({
      _id: { $in: memberIds },
      teamCode: req.user.teamCode,
      role: "member",
    }).select("_id");
    const project = await Project.create({
      teamCode: req.user.teamCode,
      name: name.trim(),
      description: description.trim(),
      memberIds: validMembers.map((member) => member._id),
      createdBy: req.user.userId,
    });
    await writeAudit({
      teamCode: req.user.teamCode,
      actorId: req.user.userId,
      action: "project.created",
      entityType: "Project",
      entityId: project._id,
      details: { name: project.name },
    });
    res.status(201).json({ success: true, project });
  } catch (err) {
    res.status(err.code === 11000 ? 409 : 500).json({
      success: false,
      message:
        err.code === 11000
          ? "A project with this name already exists"
          : err.message,
    });
  }
});

app.patch(
  "/api/admin/projects/:projectId",
  authMiddleware,
  adminAuth,
  async (req, res) => {
    try {
      const { name, description, memberIds, status } = req.body;
      const project = await Project.findOne({
        _id: req.params.projectId,
        teamCode: req.user.teamCode,
      });
      if (!project)
        return res
          .status(404)
          .json({ success: false, message: "Project not found" });
      if (name !== undefined) project.name = name.trim();
      if (description !== undefined) project.description = description.trim();
      if (status !== undefined && ["active", "archived"].includes(status))
        project.status = status;
      if (Array.isArray(memberIds)) {
        const validMembers = await User.find({
          _id: { $in: memberIds },
          teamCode: req.user.teamCode,
          role: "member",
        }).select("_id");
        project.memberIds = validMembers.map((member) => member._id);
      }
      await project.save();
      await writeAudit({
        teamCode: req.user.teamCode,
        actorId: req.user.userId,
        action: "project.updated",
        entityType: "Project",
        entityId: project._id,
        details: { name: project.name, status: project.status },
      });
      res.json({ success: true, project });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  },
);

app.post("/api/leave", authMiddleware, async (req, res) => {
  try {
    const { startDate, endDate, reason } = req.body;
    const start = new Date(`${startDate}T00:00:00`);
    const end = new Date(`${endDate}T23:59:59`);
    if (
      !startDate ||
      !endDate ||
      Number.isNaN(start.getTime()) ||
      Number.isNaN(end.getTime()) ||
      end < start ||
      !reason?.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Valid dates and a reason are required",
      });
    }
    const leave = await LeaveRequest.create({
      teamCode: req.user.teamCode,
      userId: req.user.userId,
      startDate: start,
      endDate: end,
      reason: reason.trim(),
    });
    await writeAudit({
      teamCode: req.user.teamCode,
      actorId: req.user.userId,
      action: "leave.requested",
      entityType: "LeaveRequest",
      entityId: leave._id,
    });
    const admin = await User.findOne({
      teamCode: req.user.teamCode,
      role: "admin",
    });
    if (admin)
      await sendNotificationEmail({
        to: admin.email,
        subject: "New leave request",
        message: `${req.user.userId} submitted a leave request from ${startDate} to ${endDate}.`,
      });
    res.status(201).json({ success: true, leave });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get("/api/leave", authMiddleware, async (req, res) => {
  try {
    const filter = { teamCode: req.user.teamCode };
    if (req.user.role !== "admin") filter.userId = req.user.userId;
    const leaves = await LeaveRequest.find(filter)
      .populate("userId", "name email")
      .sort({ createdAt: -1 });
    res.json({ success: true, leaves });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.patch(
  "/api/admin/leave/:leaveId",
  authMiddleware,
  adminAuth,
  async (req, res) => {
    try {
      const { status } = req.body;
      if (!["approved", "rejected"].includes(status))
        return res
          .status(400)
          .json({ success: false, message: "Invalid leave status" });
      const leave = await LeaveRequest.findOne({
        _id: req.params.leaveId,
        teamCode: req.user.teamCode,
      }).populate("userId", "name email");
      if (!leave)
        return res
          .status(404)
          .json({ success: false, message: "Leave request not found" });
      leave.status = status;
      leave.reviewedBy = req.user.userId;
      leave.reviewedAt = new Date();
      await leave.save();
      await writeAudit({
        teamCode: req.user.teamCode,
        actorId: req.user.userId,
        action: `leave.${status}`,
        entityType: "LeaveRequest",
        entityId: leave._id,
      });
      await sendNotificationEmail({
        to: leave.userId.email,
        subject: `Leave request ${status}`,
        message: `Your leave request from ${leave.startDate.toISOString().slice(0, 10)} to ${leave.endDate.toISOString().slice(0, 10)} was ${status}.`,
      });
      res.json({ success: true, leave });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  },
);

// =====================================================================
// ADMIN DASHBOARD
// =====================================================================
app.get("/api/admin/overview", authMiddleware, adminAuth, async (req, res) => {
  try {
    const teamCode = req.user.teamCode;
    const totalMembers = await User.countDocuments({ teamCode });
    const activeNow = await WorkLog.countDocuments({ teamCode, endTime: null });

    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const todayLogs = await WorkLog.find({
      teamCode,
      startTime: { $gte: startOfDay },
    });
    const totalSecondsToday = todayLogs.reduce(
      (sum, l) => sum + (l.totalSeconds || 0),
      0,
    );

    res.json({
      totalMembers,
      activeNow,
      hoursToday: Math.round((totalSecondsToday / 3600) * 10) / 10,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get("/api/admin/report", authMiddleware, adminAuth, async (req, res) => {
  try {
    const date = req.query.date || new Date().toISOString().slice(0, 10);
    const dayStart = new Date(`${date}T00:00:00`);
    const dayEnd = new Date(dayStart);
    dayEnd.setDate(dayEnd.getDate() + 1);
    if (Number.isNaN(dayStart.getTime())) {
      return res
        .status(400)
        .json({ success: false, message: "Date must be YYYY-MM-DD" });
    }

    const [members, logs] = await Promise.all([
      User.find({ teamCode: req.user.teamCode }).select(
        "name email role status",
      ),
      WorkLog.find({
        teamCode: req.user.teamCode,
        startTime: { $lt: dayEnd },
        $or: [{ endTime: { $gte: dayStart } }, { endTime: null }],
      }),
    ]);

    const report = members.map((member) => {
      const memberLogs = logs.filter(
        (log) => log.userId.toString() === member._id.toString(),
      );
      const totalSeconds = memberLogs.reduce((sum, log) => {
        const start = new Date(log.startTime);
        const end = log.endTime ? new Date(log.endTime) : new Date();
        const overlapStart = start < dayStart ? dayStart : start;
        const overlapEnd = end > dayEnd ? dayEnd : end;
        const seconds = Math.max(
          0,
          Math.floor((overlapEnd - overlapStart) / 1000),
        );
        return sum + seconds;
      }, 0);
      return {
        id: member._id,
        name: member.name,
        email: member.email,
        role: member.role,
        status: member.status,
        hours: Math.round((totalSeconds / 3600) * 100) / 100,
        sessions: memberLogs.length,
        screenshots: memberLogs.reduce(
          (sum, log) => sum + log.screenshots.length,
          0,
        ),
      };
    });

    res.json({ success: true, date, report });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get(
  "/api/admin/timesheets",
  authMiddleware,
  adminAuth,
  async (req, res) => {
    try {
      const date = req.query.date || new Date().toISOString().slice(0, 10);
      const dayStart = new Date(`${date}T00:00:00`);
      const dayEnd = new Date(dayStart);
      dayEnd.setDate(dayEnd.getDate() + 1);
      if (Number.isNaN(dayStart.getTime()))
        return res
          .status(400)
          .json({ success: false, message: "Date must be YYYY-MM-DD" });
      const logs = await WorkLog.find({
        teamCode: req.user.teamCode,
        startTime: { $gte: dayStart, $lt: dayEnd },
      })
        .populate("userId", "name email")
        .populate("projectId", "name")
        .sort({ startTime: -1 });
      res.json({ success: true, date, timesheets: logs });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  },
);

app.patch(
  "/api/admin/timesheets/:logId/approval",
  authMiddleware,
  adminAuth,
  async (req, res) => {
    try {
      const { status } = req.body;
      if (!["approved", "rejected", "pending"].includes(status))
        return res
          .status(400)
          .json({ success: false, message: "Invalid approval status" });
      const log = await WorkLog.findOne({
        _id: req.params.logId,
        teamCode: req.user.teamCode,
      }).populate("userId", "name email");
      if (!log)
        return res
          .status(404)
          .json({ success: false, message: "Timesheet not found" });
      log.approvalStatus = status;
      log.approvedBy = status === "pending" ? undefined : req.user.userId;
      log.approvedAt = status === "pending" ? undefined : new Date();
      await log.save();
      await writeAudit({
        teamCode: req.user.teamCode,
        actorId: req.user.userId,
        action: `timesheet.${status}`,
        entityType: "WorkLog",
        entityId: log._id,
      });
      if (status !== "pending")
        await sendNotificationEmail({
          to: log.userId.email,
          subject: `Timesheet ${status}`,
          message: `Your timesheet for ${log.startTime.toISOString().slice(0, 10)} was ${status}.`,
        });
      res.json({ success: true, timesheet: log });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  },
);

app.get(
  "/api/admin/report.csv",
  authMiddleware,
  adminAuth,
  async (req, res) => {
    try {
      const date = req.query.date || new Date().toISOString().slice(0, 10);
      const dayStart = new Date(`${date}T00:00:00`);
      const dayEnd = new Date(dayStart);
      dayEnd.setDate(dayEnd.getDate() + 1);
      if (Number.isNaN(dayStart.getTime()))
        return res
          .status(400)
          .json({ success: false, message: "Date must be YYYY-MM-DD" });
      const logs = await WorkLog.find({
        teamCode: req.user.teamCode,
        startTime: { $gte: dayStart, $lt: dayEnd },
      })
        .populate("userId", "name email")
        .populate("projectId", "name");
      const rows = [
        "Member,Email,Project,Start,End,Hours,Approval,Screenshots",
      ];
      for (const log of logs) {
        rows.push(
          [
            csvCell(log.userId?.name),
            csvCell(log.userId?.email),
            csvCell(log.projectId?.name),
            csvCell(log.startTime.toISOString()),
            csvCell(log.endTime?.toISOString() || ""),
            csvCell(Math.round(((log.totalSeconds || 0) / 3600) * 100) / 100),
            csvCell(log.approvalStatus),
            csvCell(log.screenshots.length),
          ].join(","),
        );
      }
      res
        .set({
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": `attachment; filename="timetracker-${date}.csv"`,
        })
        .send(rows.join("\n"));
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  },
);

app.get("/api/admin/audit", authMiddleware, adminAuth, async (req, res) => {
  try {
    const logs = await AuditLog.find({ teamCode: req.user.teamCode })
      .populate("actorId", "name email")
      .sort({ createdAt: -1 })
      .limit(200);
    res.json({ success: true, logs });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get("/api/admin/team", authMiddleware, adminAuth, async (req, res) => {
  try {
    const teamCode = req.user.teamCode;
    const members = await User.find({ teamCode }).select(
      "name email role status lastActiveAt",
    );

    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);

    const results = await Promise.all(
      members.map(async (m) => {
        const openSession = await WorkLog.findOne({
          userId: m._id,
          endTime: null,
        });
        const todayLogs = await WorkLog.find({
          userId: m._id,
          startTime: { $gte: startOfDay },
        });
        const totalSecondsToday = todayLogs.reduce(
          (sum, l) => sum + (l.totalSeconds || 0),
          0,
        );

        return {
          id: m._id,
          name: m.name,
          email: m.email,
          role: m.role,
          status: m.status,
          lastActiveAt: m.lastActiveAt,
          online: !!openSession,
          hoursToday: Math.round((totalSecondsToday / 3600) * 10) / 10,
        };
      }),
    );

    res.json({ success: true, members: results });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Admin can pause or restore a member without deleting their history.
app.patch(
  "/api/admin/team/:userId/status",
  authMiddleware,
  adminAuth,
  async (req, res) => {
    try {
      const { status } = req.body;
      if (!["active", "inactive"].includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Status must be active or inactive",
        });
      }

      const member = await User.findOne({
        _id: req.params.userId,
        teamCode: req.user.teamCode,
        role: "member",
      });
      if (!member)
        return res
          .status(404)
          .json({ success: false, message: "Team member not found" });

      member.status = status;
      await member.save();

      await writeAudit({
        teamCode: req.user.teamCode,
        actorId: req.user.userId,
        action: `member.${status}`,
        entityType: "User",
        entityId: member._id,
        details: { email: member.email },
      });

      if (status === "inactive") {
        await WorkLog.updateMany(
          { userId: member._id, endTime: null },
          { $set: { endTime: new Date() } },
        );
      }

      res.json({ success: true, status: member.status });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  },
);

// List screenshot metadata for one member on one date — image bytes are
// fetched separately (see /api/admin/screenshot-file) so nothing here is
// viewable without an admin's auth token.
app.get(
  "/api/admin/screenshots",
  authMiddleware,
  adminAuth,
  async (req, res) => {
    try {
      const { userId, date } = req.query; // date: YYYY-MM-DD
      if (!userId || !date) {
        return res
          .status(400)
          .json({ success: false, message: "userId and date are required" });
      }

      const member = await User.findOne({
        _id: userId,
        teamCode: req.user.teamCode,
      });
      if (!member) {
        return res
          .status(404)
          .json({ success: false, message: "Team member not found" });
      }

      const dayStart = new Date(date);
      dayStart.setHours(0, 0, 0, 0);
      const dayEnd = new Date(dayStart);
      dayEnd.setDate(dayEnd.getDate() + 1);

      const logs = await WorkLog.find({
        userId,
        startTime: { $gte: dayStart, $lt: dayEnd },
      });

      const shots = [];
      for (const log of logs) {
        for (const s of log.screenshots) {
          shots.push({
            workLogId: log._id,
            screenshotId: s._id,
            timestamp: s.timestamp,
            url: `/api/admin/screenshot-file/${log._id}/${s._id}`,
          });
        }
      }
      shots.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

      res.json({
        success: true,
        member: { name: member.name, email: member.email },
        screenshots: shots,
      });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  },
);

// Secured file stream. Accepts the JWT either via the normal Authorization
// header OR a ?token= query param, since an <img> tag can't send headers.
app.get(
  "/api/admin/screenshot-file/:workLogId/:screenshotId",
  async (req, res) => {
    try {
      const bearer = req.header("Authorization")?.replace("Bearer ", "");
      const token = bearer || req.query.token;
      if (!token)
        return res
          .status(401)
          .json({ success: false, message: "Access denied" });

      let decoded;
      try {
        decoded = jwt.verify(token, JWT_SECRET);
      } catch {
        return res
          .status(401)
          .json({ success: false, message: "Invalid token" });
      }
      const currentUser = await User.findById(decoded.userId).select(
        "role status teamCode",
      );
      if (
        !currentUser ||
        currentUser.status !== "active" ||
        currentUser.role !== "admin"
      ) {
        return res.status(403).json({ success: false, message: "Admin only" });
      }

      const log = await WorkLog.findById(req.params.workLogId);
      if (!log || log.teamCode !== currentUser.teamCode) {
        return res.status(404).json({ success: false, message: "Not found" });
      }
      const shot = log.screenshots.id(req.params.screenshotId);
      if (!shot)
        return res.status(404).json({ success: false, message: "Not found" });

      const filePath = path.join(uploadDir, shot.fileName);
      if (
        path.dirname(path.resolve(filePath)) !== path.resolve(uploadDir) ||
        path.basename(shot.fileName) !== shot.fileName
      ) {
        return res
          .status(400)
          .json({ success: false, message: "Invalid screenshot file" });
      }
      if (!fs.existsSync(filePath)) {
        return res
          .status(404)
          .json({ success: false, message: "File missing" });
      }
      res.sendFile(filePath);
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  },
);

app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`),
);
