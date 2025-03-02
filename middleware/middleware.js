require("dotenv").config();
const jwt = require("jsonwebtoken");
const secret_key = process.env.PROJECT_SECRET_KEY;

const send_otp = async (transport, mail, user_text) => {
  let mailoptions = {
    from: process.env.MY_EMAIL,
    to: mail,
    subject: "Your OTP Code",
    text: `Your OTP is: ${user_text}`,
  };

  try {
    let info = await transport.sendMail(mailoptions);
    console.log("Email sent successfully:", info.response);
    return info.accepted.length > 0;
  } catch (err) {
    console.error("Error sending email:", err.message);
    return false;
  }
};

const create_otp = (num) => {
  return Array.from({ length: num }, () => Math.floor(Math.random() * 10)).join("");
};

const gen_jwtToken = async (payload) => {
  try {
    if (!secret_key) {
      throw new Error(
        "PROJECT_SECRET_KEY is missing in environment variables."
      );
    }

    return jwt.sign(payload, secret_key, { expiresIn: "1h" }); // 🔹 Added token expiry
  } catch (error) {
    console.error("JWT Generation Error:", error.message);
    throw new Error("Failed to generate token");
  }
};

const verify_user_otp = async (token, otp) => {
  try {
    if (!secret_key) {
      throw new Error(
        "PROJECT_SECRET_KEY is missing in environment variables."
      );
    }

    const user_data = jwt.verify(token, secret_key);

    console.log("Received OTP:", otp, "Stored OTP:", user_data.otp);

    return user_data.otp == otp;
  } catch (error) {
    console.error("Token verification failed:", error.message);
    return false;
  }
};

const get_user_data = (token) => {
  try {
    return jwt.verify(token, secret_key);
  } catch (error) {
    console.error("Error extracting user data:", error.message);
    return null;
  }
};

module.exports = {
  send_otp,
  create_otp,
  gen_jwtToken,
  verify_user_otp,
  get_user_data,
};
