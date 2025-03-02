const baseurl = `http://localhost:5000`; // Ensure backend runs on port 3001

// Handle OTP Verification (Token is included automatically)
const handleOtp = async (e) => {
    e.preventDefault();

    const otpInputs = document.querySelectorAll(".otp-input");
    let otp = "";
    otpInputs.forEach(input => otp += input.value.trim());

    if (otp.length !== 6) {
        alert("Please enter a valid 6-digit OTP.");
        return;
    }

    try {
        if (otpBtn) {
            otpBtn.disabled = true;
            otpBtn.textContent = "Verifying...";
        }

        // Directly send OTP to backend without manually verifying token
        const response = await fetch(`${baseurl}/verify-otp`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ otp }), // No token needed in request body
        });

        const data = await response.json();
        console.log("OTP Response:", data);

        if (data.success) {
            localStorage.setItem("authtoken", data.authToken);
            alert("OTP verified successfully! Redirecting to dashboard...");
            window.location.href = "./home_page.html";
        } else {
            alert(data.message || "OTP verification failed.");
        }
    } catch (error) {
        console.error("OTP Verification Error:", error);
        alert("Error verifying OTP. Please try again.");
    } 
};

// Auto-check authentication when OTP page loads
document.addEventListener("DOMContentLoaded", function () {
    if (window.location.pathname.includes("otp.html")) {
        console.log("OTP page detected, setting up event listeners...");
        
        const otpForm = document.getElementById("otp-form");
        if (otpForm) {
            otpForm.addEventListener("submit", handleOtp);
        }
    }
});
