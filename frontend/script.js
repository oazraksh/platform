const authWrapper = document.querySelector('.auth-wrapper');
const loginTrigger = document.querySelector('.login-trigger');
const registerTrigger = document.querySelector('.register-trigger');
const messageBox = document.getElementById("messageBox");

console.log("script loaded!");

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

  const response = await fetch('http://localhost:3000/adduser', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password })
  });

  const data = await response.json();
  messageBox.innerText = data.message;

  // بعد از ثبت‌نام، کاربر رو به بخش Verify هدایت کن
  document.querySelector('h3').scrollIntoView();
});

// Verify OTP
async function verifyAccount() {
  const email = document.getElementById('verifyEmail').value;
  const otp = document.getElementById('verifyOtp').value;

  const response = await fetch('http://localhost:3000/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, otp })
  });

  const data = await response.json();
  messageBox.innerText = data.message;
}

// ورود
document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("loginEmail").value;
  const password = document.getElementById("loginPassword").value;

  const res = await fetch("http://localhost:3000/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();
  if (data.token) {
    localStorage.setItem("token", data.token); // ذخیره توکن
    messageBox.innerText = "Login successful!";
  } else {
    messageBox.innerText = data.message;
  }
});

// پروفایل (Protected Route)
document.getElementById("profileBtn").addEventListener("click", async () => {
  const token = localStorage.getItem("token");
  if (!token) {
    messageBox.innerText = "Please login first!";
    return;
  }

  const res = await fetch("http://localhost:3000/profile", {
    method: "GET",
    headers: { "Authorization": "Bearer " + token }
  });

  const data = await res.json();
  if (data.user) {
    messageBox.innerText = "Welcome " + data.user.email + "!";
  } else {
    messageBox.innerText = data.message;
  }
});