# Quickly Deployment Guide on Render with Zoho Mail OAuth 2.0

This guide outlines how to deploy **Quickly** with native **Zoho Mail OAuth 2.0** support to **Render**.

---

## 1. Quick Overview of What Was Added
- **Full Zoho Mail OAuth 2.0 Engine**: Authorization, callback handler, secure token refresh, and Zoho REST API mail sender.
- **Frontend Integration**:
  - Inboxes page: Added **Zoho Mail** to provider dropdown, OAuth check, and 1-click **Connect with Zoho** flow.
  - Settings page: Dedicated **Zoho Mail OAuth** setup under the *Setup* tab to easily view your Redirect URI, configure Client ID, Client Secret, and choose region (`.com`, `.eu`, `.in`, etc.).
- **Automatic Database Migrations**: `zoho_account` table created automatically upon startup.

---

## 2. Deploying to Render

### Method A: Render Blueprint (Recommended)
1. Push this repository to your GitHub account (e.g. `github.com/<your-username>/quickly`).
2. Go to [Render Dashboard](https://dashboard.render.com).
3. Click **New +** -> **Blueprint**.
4. Select your GitHub repository.
5. Render will automatically detect `render.yaml` and configure:
   - A **PostgreSQL Database** (`quickly-postgres`)
   - A **Web Service** (`quickly-app`) built via Dockerfile.
6. Under environment variables for `quickly-app`, fill in:
   - `BASE_URL`: `https://quickly-app-xxxx.onrender.com` (your Render service URL).
   - `ZOHO_CLIENT_ID`: Your Zoho Client ID (e.g. `1000.7JLGO...`).
   - `ZOHO_CLIENT_SECRET`: Your Zoho Client Secret.
   - `ZOHO_REGION`: `com` (or `eu`, `in`, `com.au`, etc.).

---

### Method B: Manual Web Service Setup
1. **Create Database**:
   - In Render, click **New +** -> **PostgreSQL**.
   - Name: `quickly-db`.
   - Copy the **Internal Database URL**.
2. **Create Web Service**:
   - Click **New +** -> **Web Service**.
   - Select your repository.
   - Environment / Runtime: **Docker**.
   - Dockerfile Path: `./Dockerfile`.
   - Add Environment Variables:
     - `DATABASE_URL`: *(paste the Internal Database URL)*
     - `BASE_URL`: `https://your-service-name.onrender.com`
     - `QUICKLY_SECRET_KEY`: *(generate a random string or click generate)*
     - `QUICKLY_ENCRYPTION_KEY`: *(generate a random key or leave empty to auto-generate)*
     - `ZOHO_CLIENT_ID`: Your Zoho Client ID.
     - `ZOHO_CLIENT_SECRET`: Your Zoho Client Secret.
     - `ZOHO_REGION`: `com`
3. Click **Deploy Web Service**.

---

## 3. Zoho API Console Configuration

1. Go to [Zoho Developer Console](https://api-console.zoho.com).
2. Open your Client (or create a **Server-based Applications** client).
3. In **Client Details**:
   - **Authorized Redirect URIs**:
     ```
     https://your-service-name.onrender.com/oauth/zoho/callback
     ```
     *(If running locally: `http://localhost:8000/oauth/zoho/callback`)*
   - Save the changes.

---

## 4. Connecting Your Zoho Mail Inbox in Quickly

1. Open your deployed Quickly application in your browser.
2. Complete the initial admin registration (username and password).
3. Go to **Inboxes** in the sidebar.
4. Click **Add Inbox**.
5. Select **Provider**: **Zoho Mail**.
6. Set your daily sending limits and warmup options if desired.
7. Click **Connect with Zoho**.
8. Consent to the Zoho permissions (`ZohoMail.messages.ALL`, `ZohoMail.accounts.READ`, `offline_access`).
9. You will be redirected back to Quickly with your Zoho Mail account connected and ready to send!
