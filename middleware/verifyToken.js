const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET;
function verifyToken(req, res, next) {

  const authHeader = req.headers.authorization;
  console.log("AUTH HEADER:", req.headers.authorization);
  if (!authHeader) {
    return res.status(401).json({
      message: "Token tidak ditemukan",
    });
  }

  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Format token salah",
    });
  }

  const token = authHeader.split(" ")[1];

  try {

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();

  } catch (err) {

    if (err.name === "TokenExpiredError") {
      return res.status(401).json({
        message: "Token expired",
      });
    }

    return res.status(401).json({
      message: "Token tidak valid",
    });
  }
}

module.exports = verifyToken;
