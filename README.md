# SecureLife Insurance Portal

A deployment-ready replacement for the original static insurance project.

## Features
- Secure customer registration/login with bcrypt password hashing and JWT sessions
- PostgreSQL persistence
- Policy applications and admin approval
- Claim submission and status tracking
- Premium payment records with admin verification (record-keeping only; no card/bank charging)
- Public support enquiries
- Admin dashboard for users, policies, claims, payments and enquiries
- Password change flow
- Security headers, rate limiting, input validation and protected admin APIs
- Responsive single-page UI

## Environment variables
Set `DATABASE_URL`, `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and optionally `DB_SSL`.

## Run
```bash
npm install
npm start
```

Health check: `GET /api/health`
