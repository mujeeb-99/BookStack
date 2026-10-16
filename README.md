# BookStack Library Management

A responsive library dashboard built with React, Vite, Tailwind CSS, Express, and MongoDB.

## Features

- Library overview with circulation metrics, popular titles, upcoming returns, events, and collection breakdown.
- Catalog view with search, availability, and a working add-book form.
- Separate reader and admin views, with a reader book-request workflow and an admin approval inbox.
- Public catalog home, reader registration/login, and a seeded admin login with role-restricted operations.
- Admin PDF e-book uploads stored in MongoDB Atlas GridFS (30 MB maximum); approved readers can open the PDF during the active loan.
- Member registration/removal, book issuing/returning, and 14-day loan renewals.
- Express REST endpoints backed by MongoDB via Mongoose.
- Dashboard uses sample presentation data when the API is unavailable; book creation connects to MongoDB when the API is running.

## Run locally

1. Install Node.js and create a MongoDB Atlas cluster.
2. In Atlas, add your current IP address under **Network Access** and create a database user under **Database Access**.
3. Open PowerShell in this project folder:
   ```powershell
   cd "C:\Users\Mujee\Documents\Codex\2026-10-16\create-a-libaray-managem\outputs\folio-library"
   ```
4. Install the packages:
   ```powershell
   npm install
   ```
5. Make sure `.env` exists in this folder. Copy `.env.example` to `.env` if needed, then put your Atlas connection string in `MONGODB_URI`. Set a strong `JWT_SECRET` and admin credentials with `ADMIN_USERNAME` and `ADMIN_PASSWORD`. Never share `.env` or commit it.
6. In the first PowerShell window, start the API:
   ```powershell
   npm run server
   ```
7. Open a second PowerShell window, go to the same folder, and start the web app:
   ```powershell
   cd "C:\Users\Mujee\Documents\Codex\2026-10-16\create-a-libaray-managem\outputs\folio-library"
   npm run dev
   ```
8. Open **http://localhost:5173** in your browser. Keep both terminal windows open while using BookStack.

Keep `.env` private; it is ignored by Git. Do not commit database or admin credentials.

The Vite dev server proxies `/api` requests to `http://localhost:4000`. In production, serve the built frontend and API behind a same-origin reverse proxy.

## GitHub Pages

The `main` branch deploys the frontend to GitHub Pages through the included GitHub Actions workflow. In the repository, open **Settings → Pages** and set **Build and deployment → Source** to **GitHub Actions**. After the workflow completes, the site is available at `https://mujeeb-99.github.io/BookStack/`.

GitHub Pages only hosts static frontend files. It cannot run this project's Express API or securely connect to MongoDB Atlas, so login, registration, requests, circulation, member administration, and PDF uploads need the API hosted separately. Configure that API with HTTPS and a restricted Atlas database user before connecting a public frontend; never put Atlas credentials in frontend code or GitHub Pages settings.

## API

- `GET /api/health` — service and database status.
- `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`, and `POST /api/auth/logout` — reader accounts and cookie sessions.
- `GET /api/books` — list catalog records.
- `POST /api/books` — add a book (`title`, `author`, `genre`, `isbn`, `total`).
- `POST /api/books/ebook` — upload a PDF e-book and catalog metadata as multipart form data (`title`, `author`, `genre`, `isbn`, `file`). PDFs are limited to 30 MB and stored in the Atlas `ebooks` GridFS bucket.
- `GET /api/books/:id/ebook` — open the stored PDF.
- `PATCH /api/books/:id` — update a book.
- `DELETE /api/books/:id` — remove a book.
- `GET /api/members`, `POST /api/members`, and `DELETE /api/members/:id` — browse, register, and remove members. A member with active loans cannot be removed.
- `GET /api/requests`, `POST /api/requests`, and `PATCH /api/requests/:id/review` — create reader requests and approve/decline them. Approval creates a loan and decrements available inventory.
- `GET /api/loans` and `POST /api/loans` — browse and create active loans; checkout decrements available inventory.
- `PATCH /api/loans/:id/return` — close an active loan and restore inventory.
- `PATCH /api/loans/:id/reissue` — extend an active loan (defaults to 14 days; maximum 60).

The public home page only lists books. Use the admin username configured by `ADMIN_USERNAME` and password configured by `ADMIN_PASSWORD` to sign in; the API creates/updates that admin in MongoDB with a scrypt password hash at startup. Reader registration creates a linked member account; readers can request books and view only their own requests and loans. Admin-only endpoints protect the member list, catalog changes, circulation actions, request reviews, and ebook uploads. E-book access requires an approved active loan. Use HTTPS in deployment so secure session cookies are enabled, and set a strong persistent `JWT_SECRET`.
