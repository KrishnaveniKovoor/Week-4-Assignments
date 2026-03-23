import exp from "express";
import { config } from "dotenv";
import { connect } from "mongoose";
import { userApp } from "./APIs/UserAPI.js";
import { authorApp } from "./APIs/AuthorAPI.js";
import { adminApp } from "./APIs/AdminAPI.js";
import { commonApp } from "./APIs/CommonAPI.js";
import cookieParser from "cookie-parser";

config();

// create express app
const app = exp();

// cookie parser middleware
app.use(cookieParser());

// body parser middleware
app.use(exp.json());

// path-level middlewares
app.use("/user-api", userApp);
app.use("/author-api", authorApp);
app.use("/admin-api", adminApp);
app.use("/auth", commonApp);

// connect to db
const connectDB = async () => {
  try {
    await connect(process.env.DB_URL);
    console.log("DB server connected");

    const port = process.env.PORT || 5000;
    app.listen(port, () =>
      console.log(`server listening on ${port}..`)
    );
  } catch (err) {
    console.log("err in db connect", err);
  }
};

connectDB();

// invalid path handler
app.use((req, res) => {
  res.status(404).json({ message: `path ${req.url} is invalid` });
});

// error handling middleware
app.use((err, req, res, next) => {
  console.log("error is ", err);

  if (err.name === "ValidationError") {
    return res.status(400).json({ message: "error occurred", error: err.message });
  }

  if (err.name === "CastError") {
    return res.status(400).json({ message: "error occurred", error: err.message });
  }

  const errCode = err.code ?? err.cause?.code;
  const keyValue = err.keyValue ?? err.cause?.keyValue;

  if (errCode === 11000) {
    const field = Object.keys(keyValue)[0];
    return res.status(409).json({
      message: "error occurred",
      error: `${field} already exists`,
    });
  }

  res.status(500).json({ message: "error occurred", error: "Server side error" });
});