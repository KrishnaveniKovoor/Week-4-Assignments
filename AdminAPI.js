import exp from "express";
import { UserModel } from "../Models/UserModel.js";
import verifyToken from "../middlewares/VerifyToken.js";

export const adminApp = exp.Router();

// Read all USERS and AUTHORS (email, role)
adminApp.get("/users", verifyToken("ADMIN"), async (req, res) => {
  try {
    const usersList = await UserModel.find(
      { role: { $in: ["USER", "AUTHOR"] } },
      { email: 1, role: 1 }
    );

    res.status(200).json({ message: "users", payload: usersList });
  } catch (err) {
    res.status(500).json({ message: "error occurred", error: err.message });
  }
});

// Activate / Deactivate user
adminApp.patch("/users", verifyToken("ADMIN"), async (req, res) => {
  try {
    const { userId, isUserActive } = req.body;

    const user = await UserModel.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "Invalid user" });
    }

    if (user.isUserActive === isUserActive) {
      return res.status(200).json({ message: "User already in same state" });
    }

    user.isUserActive = isUserActive;
    await user.save();

    res.status(200).json({ message: "User status updated", payload: user });
  } catch (err) {
    res.status(500).json({ message: "error occurred", error: err.message });
  }
});