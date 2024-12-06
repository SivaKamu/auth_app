**Authentication App with OTP Verification**
A Node.js-based authentication system that uses OTP (One-Time Password) verification for user registration and login. The app includes features such as email-based OTP validation, hashed password storage, and JWT-based authentication for secure session management.

**Features**
1. User Registration with OTP verification.
2. Login with OTP verification.
3. Password hashing for secure storage (using bcryptjs).
4. OTP expiration handling (valid for 5 minutes).
5. Email-based OTP delivery using Nodemailer.
6. JWT-based token generation for secure authentication.

**Folder Structure**
auth_app/
├── config/
│   └── db.js          # Database connection configuration
├── controllers/
│   └── authController.js # Logic for user registration, login, and OTP verification
├── middleware/
│   └── authMiddleware.js # JWT-based authentication middleware (if needed)
├── models/
│   └── User.js         # Mongoose schema for User
├── routes/
│   └── authRoutes.js   # Routes for authentication-related APIs
├── utils/
│   └── sendOTPEmail.js # Helper function for sending OTP emails
├── .env                # Environment variables
├── package.json        # Project dependencies and scripts
├── README.md           # Project documentation
├── server.js           # Entry point of the app

**Getting Started**
**Prerequisites**
Ensure you have the following installed:

Node.js (v14 or higher)
MongoDB (Local or cloud-based, e.g., MongoDB Atlas)

**Installation**
**step - 1**
Clone the repository:
_git clone https://github.com/your-username/auth-app.git
cd auth-app_

**step - 2**
Install dependencies:
_npm install_

**step - 3**
Set up environment variables: Create a .env file in the root directory and add the following:
_PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_secret_key
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
OTP_EXPIRATION=5_

**step - 4**
Start the server:
_npm start_

**Running in Development Mode**
Use **nodemon** to automatically restart the server on changes:
_npm install -g nodemon
nodemon server.js_

**Security Best Practices**
Use **strong secrets** for **JWT_SECRET** in production.
Enable **2FA or App Passwords** for SMTP credentials (e.g., Gmail App Passwords).
Store sensitive credentials like **MONGO_URI and SMTP_PASS** in secure vaults (e.g., AWS Secrets Manager, Azure Key Vault).

**Future Improvements**
1. Add rate limiting for OTP requests.
2. Implement a password reset flow.
3. Support multi-factor authentication (MFA).
4. Use a more robust email service (e.g., AWS SES, SendGrid).
