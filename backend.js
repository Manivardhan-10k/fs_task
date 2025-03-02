const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");
const transport = require("./controller/mail_controller.js");
const middleware = require("./middleware/middleware.js");
const cookieParser = require("cookie-parser");
const connection = require("./model/db.js");
const app = express();

// Middleware
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Create uploads directory if it doesn’t exist
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer storage configuration
const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => {
    cb(
      null,
      file.fieldname + "-" + Date.now() + path.extname(file.originalname)
    );
  },
});

// File filter for images
const my_filter = (req, file, cb) => {
  const allowedFileTypes = /jpeg|jpg|png/;
  const ext = path.extname(file.originalname).toLowerCase();
  if (allowedFileTypes.test(file.mimetype) && allowedFileTypes.test(ext)) {
    cb(null, true);
  } else {
    cb(new Error("Only JPEG, JPG, and PNG files are allowed!"), false);
  }
};

// Multer upload configuration
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: my_filter,
});

// CORS configuration
app.use(
  cors({
    origin: "http://127.0.0.1:5500",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
  })
);

// Test endpoint
app.get("/", (req, res) => {
  res.send("Server is running!");
});

// Registration endpoint
app.post("/register", upload.single("profilePic"), async (req, res) => {

  if (!req.file) {
    return res.status(400).json({ message: "File upload failed!" });
  }

  const { name, email, mobile, password, city, age, role } = req.body;
  const file_name = req.file.filename;
  const org_name = req.file.originalname;
  const file_path = path.join(__dirname, "uploads", file_name);

  if (!name || !email || !password || !city || !mobile || !age) {
    return res.status(400).json({ message: "All fields are required!" });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const otp = middleware.create_otp(6);

  if (!middleware.send_otp(transport, email, otp)) {
    return res
      .status(500)
      .json({ success: false, message: "Failed to send OTP." });
  }

  const token = await middleware.gen_jwtToken({
    name,
    email,
    mobile,
    password: hashedPassword,
    city,
    age,
    file_name,
    org_name,
    file_path,
    role,
    otp,
  });

  if (Object.values(token).length == 0) {
    return res
      .status(500)
      .json({ success: false, message: "Failed to generate token." });
  }
//   res.cookie(
//     "userData",
//     { name, email, city, age, mobile },
//     { maxAge: 300000, httpOnly: true, secure: false, sameSite: "Strict" }
//   );
  res.cookie("token", token, {
    maxAge: 3600000,
    httpOnly: true,
    secure: false,
    sameSite: "Strict",
  });

  res
    .status(200)
    .json({
      success: true,
      message: "Registration submitted!",
      token,
      file: file_name,
    });
});

// OTP Verification endpoint
app.post("/verify-otp", async (req, res) => {
  const otp = req.body.otp;
  const token = req.cookies.token;
  console.error(token);

  if (!token || !otp) {
    return res
      .status(400)
      .json({ success: false, message: "Token and OTP are required." });
  }

  if (!middleware.verify_user_otp(token, otp)) {
    return res.status(400).json({ success: false, message: "Invalid OTP." });
  }

  const userData = middleware.get_user_data(token);
  if (!userData) {
    return res.status(400).json({ success: false, message: "Invalid token." });
  }

  const authToken = await middleware.gen_jwtToken({ userData });

  const sql =
    "INSERT INTO fs_task (name, email, mobile, password, city, age, file_name, org_name, file_path, role_type, token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  const values = [
    userData.name,
    userData.email,
    userData.mobile,
    userData.password,
    userData.city,
    userData.age,
    userData.file_name,
    userData.org_name,
    userData.file_path,
    userData.role,
    authToken,
  ];
  console.log(values);
  connection.query(sql, values, (err, result) => {
    if (err) {
        console.log(err)
      return res
        .status(500)
        .json({ success: false, message: "Failed to store the data." });
    }
    res.json({
      success: true,
      message: "OTP verified successfully",
      authToken,
    });
  });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
