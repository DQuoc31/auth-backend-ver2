# Deploying auth-backend to Render

Quick checklist & recommendations to avoid startup timeout issues on Render:

1. Build step (Render builds your app before starting it):

   - Set "Build Command" to:

     npm run build

   This generates the compiled JS files in `dist/`.

2. Start step (how Render launches the web service):

   - We added a `Procfile` so Render can use the production start command. Procfile content:

     web: npm run start:prod

   - Alternatively you can set "Start Command" to:

     npm run start:prod

3. Environment variables

   - Configure these in your Render service settings (Environment > Environment Variables):
     - `MONGODB_URI` — required, point to your hosted DB (MongoDB Atlas or Render-managed DB).
     - `PORT` — Render will provide this automatically; do not hardcode.

4. Health / startup timeouts

   - The backend previously could hang while trying to connect to MongoDB. To avoid long waits on startup when the DB is not reachable, we've added conservative Mongoose connection options (serverSelectionTimeoutMS & connectTimeoutMS). If your DB is misconfigured the app will fail faster — making deployment timeouts easier to diagnose.

5. Verify

   - Check deployment logs on Render to confirm the build finished and `node dist/main` started.
   - When running, hitting the application root `/` should return a simple `Hello World!` string (this route does not depend on DB and helps Render's health check succeed).

If you still see timeouts after following those steps, please paste the Render deploy logs and I can inspect the exact failure (DB unreachable, missing env var, build issues, etc.).
