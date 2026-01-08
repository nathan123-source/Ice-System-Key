# Key System — Deploy instructions

This repo contains a static frontend (`index.html`) and a small Node.js server (`server.js`) that uses local JSON files for storage.

Important note about hosting
- Vercel is great and free for static sites (frontend). However, Vercel serverless functions are ephemeral and NOT suitable for writing persistent JSON files. For the backend you should use a host that supports a long-running Node process (Render, Railway, Fly, etc.).

Recommended quick setup (frontend on Vercel, backend on Render):

1) Create a GitHub repo and push this project.

2) Deploy frontend to Vercel:
   - Go to https://vercel.com, sign in and import the GitHub repo.
   - Vercel will auto-detect a static project and deploy `index.html` as the site.

3) Deploy backend to Render (free web service):
   - Go to https://render.com and create a free account.
   - Create a new Web Service > Connect repo > Select this repo.
   - Build command: leave empty. Start command: `node server.js`.
   - Set the port to `3000` (the app listens on process.env.PORT or 3000).
   - Deploy. Render will provide a public URL like `https://your-app.onrender.com`.

4) In the admin UI (served by the frontend), set the public API URL using the "API pública" field to the Render URL. Generate the script and share with users.

If you prefer to host both frontend and backend together on a single host that supports long-running processes (Render can also serve the static `index.html` and the API from the same service), adjust accordingly.

If you want, I can:
- prepare the repo for deployment (add `package.json`, this README) — done
- help you push to GitHub (I can show commands)
- walk you through creating Render/Vercel projects step-by-step

Choose what you want me to do next.
