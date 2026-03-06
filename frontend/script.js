const authWrapper = document.querySelector('.auth-wrapper');
const loginTrigger = document.querySelector('.login-trigger');
const registerTrigger = document.querySelector('.register-trigger');
const messageBox = document.getElementById("messageBox");

// تعیین آدرس API (لوکال یا Railway)
const API_BASE = window.location.hostname === "localhost"
  ? "http://localhost:3000"
  : "https://platform-production.up.railway.app";

// نمایش پیام‌ها با رنگ مناسب
function showMessage(msg, type = "info") {
  messageBox.innerText = msg;
  messageBox.style.color = type === "error" ? "red" : "green";
}

// سوییچ بین فرم‌ها
registerTrigger.addEventListener('click', (e) => {
  e.preventDefault();
  authWrapper.classList.add('toggled');
});

loginTrigger.addEventListener('click', (e) => {
  e.preventDefault();
  authWrapper.classList.remove('toggled');
});

// ثبت‌نام
document.getElementById('signupForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('signupUsername').value;
  const email = document.getElementById('signupEmail').value;
  const password = document.getElementById('signupPassword').value;

  const response = await fetch(`${API_BASE}/adduser`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password })
  });

  const data = await response.json();
  showMessage(data.message, data.message.includes("Error") ? "error" : "success");

  // بعد از ثبت‌نام، کاربر رو به بخش Verify هدایت کن
  document.querySelector('h3').scrollIntoView();
});

// Verify OTP
async function verifyAccount() {
  const email = document.getElementById('verifyEmail').value;
  const otp = document.getElementById('verifyOtp').value;

  const response = await fetch(`${API_BASE}/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, otp })
  });

  const data = await response.json();
  showMessage(data.message, data.message.includes("Invalid") ? "error" : "success");

  if (data.message.includes("success")) {
    // بعد از تأیید، کاربر رو به فرم ورود برگردون
    authWrapper.classList.remove('toggled');
  }
}

// ورود
document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("loginEmail").value;
  const password = document.getElementById("loginPassword").value;

  const res = await fetch(`${API_BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();
  if (data.token) {
    localStorage.setItem("token", data.token); // ذخیره توکن
    showMessage("Login successful!", "success");
  } else {
    showMessage(data.message, "error");
  }
});

// پروفایل (Protected Route)
document.getElementById("profileBtn").addEventListener("click", async () => {
  const token = localStorage.getItem("token");
  if (!token) {
    showMessage("Please login first!", "error");
    return;
  }

  const res = await fetch(`${API_BASE}/profile`, {
    method: "GET",
    headers: { "Authorization": "Bearer " + token }
  });

  const data = await res.json();
  if (data.user) {
    showMessage("Welcome " + data.user.email + "!", "success");
  } else {
    showMessage(data.message, "error");
  }
});