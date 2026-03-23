import exp from "express";
import { UserModel } from "../Models/UserModel.js";
import { hash, compare } from "bcryptjs";
import { config } from "dotenv";
import jwt from "jsonwebtoken";

const { sign } = jwt;
export const commonApp = exp.Router();
config();

// Route for register
commonApp.post("/users", async (req, res) => {
  try {
    let allowedRoles = ["USER", "AUTHOR"];
    const newUser = req.body;

    if (!allowedRoles.includes(newUser.role)) {
      return res.status(400).json({ message: "Invalid role" });
    }

    newUser.password = await hash(newUser.password, 12);

    const newUserDoc = new UserModel(newUser);
    await newUserDoc.save();

    res.status(201).json({ message: "User created" });
  } catch (err) {
    res.status(500).json({ message: "error occurred", error: err.message });
  }
});

// Route for Login
commonApp.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email" });
    }

    const isMatched = await compare(password, user.password);
    if (!isMatched) {
      return res.status(400).json({ message: "Invalid password" });
    }

    const signedToken = sign(
      { id: user._id, email: email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("token", signedToken, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
    });

    let userObj = user.toObject();
    delete userObj.password;

    res.status(200).json({ message: "login success", payload: userObj });
  } catch (err) {
    res.status(500).json({ message: "error occurred", error: err.message });
  }
});

// Route for Logout
commonApp.get("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
  });
  res.status(200).json({ message: "Logout success" });
});