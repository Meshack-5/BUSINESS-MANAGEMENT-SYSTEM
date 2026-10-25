# Business Management System

A compact full-stack business management application using Node.js, Express, MongoDB, and a single-file HTML/CSS/JavaScript frontend. The Express server serves the frontend and API from the same origin, so a separate frontend server and CORS configuration are not required.

## Included features

- Login/logout using bcrypt password hashes and an HTTP-only JWT cookie.
- Initial administrator account created from environment variables on first startup.
- Role-aware UI and administrator-only user creation/deletion of business records.
- Dashboard metrics based on MongoDB records.
- CRUD for customers, employees, products/inventory, sales, invoices, and expenses.
- Basic search, validation, low-stock list, monthly reports, and audit entries for record create/update/delete.
- Health endpoint at `/api/health`.

## Requirements

- Node.js 20 or newer.
- MongoDB running locally or a MongoDB connection URI.
- PowerShell, Command Prompt, or Git Bash on Windows.

## Run on Windows

Open a terminal in this project folder.

1. Install dependencies:

   ```powershell
   npm install
   ```

2. Create your environment file:

   ```powershell
   Copy-Item .env.example .env
   ```

   Open `.env`. Replace `JWT_SECRET` with a long random secret and set `ADMIN_EMAIL` and a unique `ADMIN_PASSWORD` of at least 12 characters. For example, you can generate a secret with:

   ```powershell
   node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
   ```

   Copy the generated output into `JWT_SECRET`. Do not commit `.env` to GitHub.

3. Make sure MongoDB is running. If installed as a Windows service, in an Administrator PowerShell window:

   ```powershell
   Start-Service MongoDB
   ```

   If your service has a different name, check it with `Get-Service *mongo*`. If you installed MongoDB without a service, start `mongod.exe` using your configured data directory instead.

4. Start the app:

   ```powershell
   npm start
   ```

5. Open `http://localhost:3000` in your browser and sign in with `ADMIN_EMAIL` and `ADMIN_PASSWORD` from `.env`.

The first successful startup creates the administrator only if the database has no users. If you later change `ADMIN_PASSWORD` in `.env`, that does not reset an existing account's password.

## API overview

All business endpoints except health and login require authentication.

- `GET /api/health`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `POST /api/auth/change-password`
- `GET /api/dashboard`
- `GET /api/reports/summary`
- `GET|POST /api/customers`
- `GET|POST /api/employees`
- `GET|POST /api/products`
- `GET|POST /api/sales`
- `GET|POST /api/invoices`
- `GET|POST /api/expenses`
- `PATCH /api/:resource/:id`
- `DELETE /api/:resource/:id` (administrator only)
- `GET|POST /api/users` (administrator only)
- `PATCH /api/users/:id/active` (administrator only)

List endpoints accept `q`, `page`, and `limit` query parameters. Amounts are stored as numeric values; the UI displays them in Kenyan shillings (KES). Confirm the currency and business rules that your organization needs before using the financial totals for accounting.

## Production deployment checklist

This repository is a compact operational foundation, not a certification that every organization-specific production requirement has been met. Before handling real customer or financial data:

- Use managed MongoDB with authentication, network restrictions, TLS, backups, and tested restore procedures.
- Set `NODE_ENV=production`, a strong unique `JWT_SECRET`, and `COOKIE_SECURE=true` when served over HTTPS.
- Set `APP_ORIGIN` to your real HTTPS origin. Terminate TLS at a trusted host/proxy.
- Add monitoring, structured logs, alerting, dependency/security scans, and automated tests.
- Define retention, privacy, audit, authorization, and recovery policies appropriate to your jurisdiction.
- Review financial workflows (invoice numbering, payment reconciliation, tax, stock adjustments, refunds, and concurrent updates). This compact version does not implement a full accounting ledger or payment-gateway integration.
- Configure an external backup schedule; do not rely on the application alone for backups.

## GitHub

```powershell
git init
git add .
git commit -m "Build business management system"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

Never commit `.env`, database credentials, JWT secrets, or production customer data.
