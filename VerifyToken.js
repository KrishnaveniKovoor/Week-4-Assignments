import jwt from "jsonwebtoken";
import { config } from "dotenv";
config();

const verifyToken = (allowedRole) => {
  return (req, res, next) => {
    try {
      //get token from cookies
      const token = req.cookies?.token;

      if (!token) {
        return res.status(401).json({ message: "Unauthorized access" });
      }

      //verify token
      const decoded = jwt.verify(token, process.env.SECRET_KEY);

      //check role
      if (allowedRole && decoded.role !== allowedRole) {
        return res.status(403).json({ message: "Forbidden access" });
      }

      //attach user info to request
      req.user = decoded;

      next();
    } catch (err) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }
  };
};

export default verifyToken;