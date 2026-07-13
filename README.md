# 🔐 Secure Authentication Service (Backend-Only)

A **production-grade authentication & authorization backend service** built with **Node.js + Express**.  
It follows modern security best practices like **JWT authentication**, **refresh token rotation**, **Redis-backed token blacklisting**, **OTP-based password reset**, **distributed rate limiting**, and **Role-Based Access Control (RBAC)**.

✅ **Deployed on Render**  
✅ **Testable via Swagger UI (No Frontend Required)**

---

## 🌍 Live Deployment

| Service                      | Link                                                 |
| ---------------------------- | ---------------------------------------------------- |
| **Backend Base URL**         | `https://secure-auth-service-lk0k.onrender.com`      |
| **Swagger Docs (Test Here)** | `https://secure-auth-service-lk0k.onrender.com/docs` |

> This is a backend-only project. Recruiters and developers can test all endpoints directly using Swagger.

---

## ⭐ Why This Project Stands Out

This is not a basic authentication API — it’s designed like a **real-world production authentication service**:

✅ Stateless JWT Authentication  
✅ Refresh Token Rotation (Secure session handling)  
✅ Redis Token Blacklisting (Instant logout / revoke sessions)  
✅ Multi-Layer Rate Limiting (IP + Login + Per-user)  
✅ OTP Password Reset System with attempt tracking  
✅ Account lock protection (Brute-force OTP prevention)  
✅ RBAC (Admin / User protected routes)  
✅ Swagger/OpenAPI docs  
✅ Joi validation middleware  
✅ Secure HTTPOnly cookie setup for refresh tokens

---

## ✨ Core Features

### ✅ Authentication & Authorization

- User registration with email verification
- Secure login with bcrypt hashing (12 salt rounds)
- JWT access token issuance (configurable expiration)
- Refresh token rotation with automatic invalidation
- Redis token blacklist for access token revocation
- Role Based Access Control (RBAC)

---

### 🛡️ Security Highlights

- **3-layer rate limiting**
    - Global IP limiting
    - Login brute-force protection (email + IP)
    - Per-user API protection for authenticated endpoints
- OTP-based password reset flow
- OTP attempt tracking + lockout for 15 minutes
- Refresh tokens stored securely (SHA-256 hashed in DB)
- Email verification enforcement (unverified users cannot log in)
- CORS configurable for trusted clients
- Refresh token stored in **HTTPOnly cookie** (prevents XSS)

---

### 👤 User Management

- `/auth/me` protected profile endpoint
- Change password (revokes all refresh tokens)
- Logout current session
- Logout all devices
- Resend verification email with cooldown protection

---

## 🛠 Tech Stack

| Component          | Technology         |
| ------------------ | ------------------ |
| Runtime            | Node.js (LTS)      |
| Framework          | Express.js         |
| Database           | MongoDB + Mongoose |
| Caching / Limiting | Redis              |
| Auth               | JWT (jsonwebtoken) |
| Hashing            | bcrypt             |
| Validation         | Joi                |
| Docs               | Swagger UI Express |

---

## 🚀 Getting Started Locally

### 1️⃣ Clone Repository

```bash
git clone https://github.com/Itsmesachin98/secure-authentication-service.git
cd secure-authentication-service
```

### 2️⃣ Install Dependencies

```bash
npm install
```

### 3️⃣ Setup Environment Variables

Create a `.env` file in the root:

```env
# Server
PORT=3000
NODE_ENV=development
BACKEND_URL=http://localhost:3000

# Database
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/secure-auth-db

# Redis
REDIS_URL=redis://localhost:6379

# For Redis Cloud
REDIS_URL=redis://:password@host:port

# JWT
JWT_ACCESS_SECRET=your-super-secret-access-token-key-min-32-chars
JWT_ACCESS_EXPIRES_IN=15m

# Email Config (Optional - for production)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
SENDER_EMAIL=noreply@yourdomain.com
```

✅ **Important:** Never commit `.env` to GitHub.

---

### 4️⃣ Run Server

```bash
npm start
```

Server will run at:

✅ `http://localhost:3000`  
✅ Swagger docs: `http://localhost:3000/docs`

---

## 📖 API Documentation

Swagger UI is available at:

✅ **Local:** `http://localhost:3000/docs`  
✅ **Production:** `https://secure-authentication-service.onrender.com/docs`

---

## 🧪 Testing the API

### ✅ Test via Swagger (Recommended)

No frontend needed → open Swagger:

👉 `https://secure-authentication-service.onrender.com/docs`

---

### ✅ Test using Postman

1. Import: `Secure-Auth-Service.postman_collection.json`
2. Set `baseUrl` to:
    ```
    https://secure-authentication-service.onrender.com
    ```

---

## 📌 Rate Limiting System

This API implements **three layers of Redis-based rate limiting**:

| Layer          | Applies To       | Limit      | Window |
| -------------- | ---------------- | ---------- | ------ |
| IP-Based       | All routes       | 200 req    | 60s    |
| Login-Specific | `/auth/login`    | 5 attempts | 10m    |
| Per-user API   | Protected routes | 100 req    | 60s    |

---

### Redis Keys Used

```txt
ip:{clientIP}
login:ip:{clientIP}
login:email:{email}
api:user:{userId}
otp:cooldown:{email}
otp:attempts:{userId}
otp:lock:{userId}
blacklist:{jti}
email:cooldown:{email}
```

---

## 🔐 Security Architecture

### Token Management

#### ✅ Access Token Flow

```txt
Login → Issue JWT (sub, role, jti) → Client uses Authorization header
→ Server verifies signature + checks Redis blacklist → Access granted
```

#### ✅ Refresh Token Flow

```txt
Login → Generate random token → SHA-256 hash stored in DB
→ HTTPOnly cookie set → Refresh endpoint rotates token (revokes old, issues new)
```

---

### 🔑 Password Security

- **Algorithm:** bcrypt with 12 salt rounds (industry standard)
- **Storage:** Password hashes are never selected by default (`select: false`)
- **Reset:** OTP-based reset system (no reset link stored permanently)

---

### 🍪 CORS & Cookie Configuration

```js
// Refresh token cookie settings
httpOnly: true; // Prevents XSS attacks
secure: true; // Only HTTPS in production
sameSite: "strict"; // CSRF protection
path: "/auth"; // Restricted to auth routes
maxAge: 7 * 24 * 60 * 60 * 1000; // 7 days
```

---

### ✅ Validation

- **Joi schemas** enforced on all POST/PUT requests
- **Input sanitization** (unknown fields stripped)
- **Password complexity rules** (uppercase, lowercase, digit, special character)
- **Email validation** follows RFC-style validation rules

---

## 🔄 Authentication Workflows

### ✅ Registration & Email Verification

```txt
User Registration
↓
Validate input (Joi schema)
↓
Check if email exists
↓
Hash password (bcrypt, 12 rounds)
↓
Create user (isEmailVerified = false)
↓
Generate email verification token (32 bytes)
↓
Hash token with SHA-256
↓
Save hashed token to user.emailVerificationToken
↓
Send verification link in response
↓
User clicks link with token
↓
Verify token hash matches
↓
Set isEmailVerified = true
↓
User can now login
```

---

### ✅ Login & Token Generation

```txt
POST /auth/login
↓
Validate email & password
↓
Fetch user with password hash
↓
Compare passwords with bcrypt
↓
Check if email is verified
↓
Revoke previous refresh tokens
↓
Generate JWT Access Token (15m default)
↓
Generate Refresh Token (64 bytes, hashed)
↓
Store hashed refresh token in DB
↓
Return access token + set refresh cookie
```

---

### ✅ Password Reset (OTP-Based)

```txt
POST /auth/forgot-password
↓
Check cooldown (60 seconds)
↓
Check account lock status
↓
Generate random 6-digit OTP
↓
Hash OTP with bcrypt
↓
Create PasswordReset document
↓
Set attempt counter (0)
↓
Send OTP to email
↓
POST /auth/verify-reset-otp
↓
Increment attempt counter
↓
If attempts > 5: lock account for 15m
↓
Compare OTP with bcrypt hash
↓
Mark reset as verified
↓
POST /auth/reset-password
↓
Check OTP is verified
↓
Hash new password
↓
Revoke all refresh tokens
↓
Delete reset session
↓
User can login with new password
```

---

## 📈 Performance Considerations

- **MongoDB Indexes:** Email uniqueness index for fast lookups
- **Redis Expiration:** Auto-cleanup using key TTL
- **Token Hashing:** SHA-256 refresh token hashing allows fast DB comparisons
- **Bcrypt Rounds:** 12 rounds balances security & performance
- **Connection Pooling:** Mongoose & Redis handle pooling automatically

---

## 📁 Project Structure

```txt
secure-authentication-service/
├── app.js
├── package.json
├── .env.example
│
├── controllers/
│   └── auth.controller.js
│
├── routes/
│   └── auth.route.js
│
├── middlewares/
│   ├── protectRoutes.js
│   ├── requireRole.js
│   ├── validateRequest.js
│   ├── ipRateLimiter.js
│   ├── loginRateLimiter.js
│   └── apiRateLimiter.js
│
├── models/
│   ├── user.model.js
│   ├── refreshToken.model.js
│   └── passwordReset.model.js
│
├── utils/
│   ├── accessToken.js
│   ├── refreshToken.js
│   ├── emailVerificationToken.js
│   └── rateLimiter.js
│
├── validators/
│   └── auth.validator.js
│
├── lib/
│   ├── db.js
│   └── redis.js
│
├── docs/
│   └── swagger.js
│
└── Secure-Auth-Service.postman_collection.json
```

---

## 🤝 Contributing

1. Fork this repo
2. Create your branch:

```bash
git checkout -b feature/new-feature
```

3. Commit changes:

```bash
git commit -m "Add new feature"
```

4. Push:

```bash
git push origin feature/new-feature
```

5. Open a Pull Request ✅

---

## 📄 License

Licensed under **ISC License**.

---

## 👨‍💻 Author

**Sachin Kumar**  
Backend Developer | Node.js | Express | MongoDB | Redis | Security  
🚀 Deployed Project: `https://secure-authentication-service.onrender.com`
