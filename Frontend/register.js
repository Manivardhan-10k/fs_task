const baseurl = `http://127.0.0.1:5000`; // Ensure backend runs on port 5000

// Handle User Registration
const handleRegister = async (event) => {
    event.preventDefault(); // Prevent default form submission
    console.log("Registering user...");

    let formData = new FormData();
    formData.append("name", document.getElementById("name")?.value.trim() || "");
    formData.append("email", document.getElementById("email")?.value.trim() || "");
    formData.append("password", document.getElementById("password")?.value.trim() || "");
    formData.append("age", document.getElementById("age")?.value.trim() || "");
    formData.append("city", document.getElementById("city")?.value.trim() || "");
    formData.append("mobile", document.getElementById("mobile")?.value.trim() || "");

    let fileInput = document.getElementById("profilePic");
    if (fileInput && fileInput.files.length > 0) {
        formData.append("profilePic", fileInput.files[0]);
    }

    try {
        // Log form data for debugging
        for (let [key, value] of formData.entries()) {
            console.log(`${key}:`, value);
        }

        // Send request to backend
        const response = await fetch(`${baseurl}/register`, {
            method: "POST",
            body: formData,
        });

        // Read raw response text
        const responseText = await response.text();
        console.log("Raw Server Response:", responseText);

        try {
            const res = JSON.parse(responseText);
            console.log("Parsed JSON Response:", res);

            if (response.ok && res.success) {
                localStorage.setItem("authtoken", res.token);
                localStorage.setItem("userData", JSON.stringify(res.data));

                console.log("Registration successful! Redirecting...");
                window.location.href = "./otp.html"; // Redirect to OTP page
            } else {
                console.error(res.message || "Registration failed.");
                alert(res.message || "Registration failed. Please try again.");
            }
        } catch (jsonError) {
            console.error("Failed to parse JSON response:", jsonError);
            alert("Unexpected server response. Please try again.");
        }
    } catch (error) {
        console.error("Registration Error:", error);
        alert("Registration failed. Please check your connection and try again.");
    }
};
