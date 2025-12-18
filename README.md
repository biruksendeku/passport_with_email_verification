# Passport Authentication with Email Verification

A Node.js authentication app built with Express, Passport.js (local strategy),
MongoDB and Nodemailer. New users must verify their email address before their
account is considered active, and unverified accounts are cleaned up
automatically after 7 days.

## Features

- Sign up / login / logout with Passport.js local strategy
- Password hashing with bcryptjs
- Email verification flow (token + expiry) sent via Nodemailer (Gmail)
- Resend verification email page
- Rate limiting on login and API routes
- Daily cron job to delete unverified accounts older than 7 days

## Getting Started

1. Install dependencies:

   ```bash
   npm install
   ```

2. Create a `.env` file in the project root with the following variables
   (see `.env.example`):

   ```
   MONGODB_URI=mongodb://localhost:27017/passport_demo
   SESSION_SECRET_KEY=change_me
   EMAIL_USER=yourgmail@gmail.com
   EMAIL_PASS=your_gmail_app_password
   BASE_URL=http://localhost:3000
   PORT=3000
   ```

3. Start the server:

   ```bash
   npm start
   ```

   For development with auto-reload:

   ```bash
   npm run dev
   ```

## Routes

| Method | Path                        | Description                          |
| ------ | --------------------------- | ------------------------------------ |
| GET    | `/signup`                   | Registration page                    |
| POST   | `/signup`                   | Create a new (unverified) user       |
| GET    | `/login`                    | Login page                           |
| POST   | `/login`                    | Authenticate and redirect to profile |
| GET    | `/profile`                  | Protected profile page               |
| GET    | `/logout`                   | Log out                              |
| GET    | `/api/verify-email/:token`  | Verify email with token              |
| GET    | `/resend-verification`      | Resend verification email page       |
| POST   | `/resend-verification`      | Send a new verification email        |

## License

MIT
