# 🚀 GitHub to Cloudflare Deployment Guide

## 📋 Prerequisites
- GitHub account (already linked to Cursor ✅)
- Cloudflare account
- Node.js installed on your system
- Git installed on your system

---

## Step 1: Create GitHub Repository

### 1.1 Create New Repository
1. Go to [GitHub.com](https://github.com)
2. Click the "+" icon in the top right corner
3. Select "New repository"
4. Name it: `secure-redirect-landing`
5. Make it **Public** (required for Cloudflare to access JSON files)
6. Add description: "Secure redirect landing page with Cloudflare Workers"
7. **DO NOT** initialize with README, .gitignore, or license (we'll add our own)
8. Click "Create repository"

### 1.2 Repository Structure
Your repository should have this structure:
```
secure-redirect-landing/
├── src/
│   └── worker.js
├── data/
│   ├── list.json
│   ├── url.json
│   ├── blacklist.txt
│   └── whitelist.json
├── package.json
├── wrangler.toml
├── setup.js
├── README.md
├── DEPLOYMENT.md
├── GITHUB_DEPLOYMENT_GUIDE.md
└── .gitignore
```

---

## Step 2: Upload Project Files to GitHub

### 2.1 Using Cursor (Recommended)
Since your GitHub is linked to Cursor, you can:

1. **Initialize Git in your project folder:**
   ```bash
   cd /c/Users/Work/Desktop/LANDING_PAGE
   git init
   git add .
   git commit -m "Initial commit: Secure redirect landing page"
   ```

2. **Add your GitHub repository as remote:**
   ```bash
   git remote add origin https://github.com/YOUR_USERNAME/secure-redirect-landing.git
   git branch -M main
   git push -u origin main
   ```

### 2.2 Alternative: Manual Upload
If you prefer manual upload:
1. Go to your GitHub repository
2. Click "Add file" → "Upload files"
3. Drag and drop all project files
4. Commit with message: "Initial commit: Secure redirect landing page"

---

## Step 3: Configure Cloudflare Account

### 3.1 Create Cloudflare Account
1. Go to [Cloudflare.com](https://cloudflare.com)
2. Sign up for a free account
3. Verify your email address

### 3.2 Install Wrangler CLI
```bash
npm install -g wrangler
```

### 3.3 Login to Cloudflare
```bash
wrangler login
```
This will open your browser to authenticate with Cloudflare.

---

## Step 4: Configure Project Settings

### 4.1 Run Setup Script
```bash
npm run setup
```

This will prompt you for:
- **Turnstile Site Key**: Get from Cloudflare Dashboard
- **Turnstile Secret Key**: Get from Cloudflare Dashboard
- **GitHub Repository URL**: Your repository URL (e.g., `https://github.com/YOUR_USERNAME/secure-redirect-landing`)

### 4.2 Get Turnstile Keys
1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Navigate to "Security" → "Turnstile"
3. Click "Add site"
4. Choose "Managed" challenge type
5. Enter your domain (can be temporary)
6. Copy the **Site Key** and **Secret Key**

### 4.3 Create KV Namespace
```bash
wrangler kv:namespace create "RATE_LIMIT_KV"
```

This will output something like:
```
🌀 Creating namespace with title "secure-redirect-landing-RATE_LIMIT_KV"
✨ Success!
Add the following to your configuration file:
[[kv_namespaces]]
binding = "RATE_LIMIT_KV"
id = "your-kv-id-here"
preview_id = "your-preview-kv-id-here"
```

### 4.4 Update wrangler.toml
Replace the placeholder KV IDs in `wrangler.toml` with the actual IDs from step 4.3.

---

## Step 5: Update GitHub Data Files

### 5.1 Configure list.json
Edit `data/list.json` to include authorized emails:
```json
{
  "emails": [
    "your-email@domain.com",
    "admin@yourcompany.com",
    "test@example.com"
  ]
}
```

### 5.2 Configure url.json
Edit `data/url.json` with your redirect URLs:
```json
{
  "urls": [
    "https://your-app.com/dashboard",
    "https://secure-portal.com/access",
    "https://admin-panel.com/login"
  ]
}
```

### 5.3 Configure blacklist.txt (Optional)
Add IP addresses to block:
```
192.168.1.100
10.0.0.50
```

### 5.4 Configure whitelist.json (Optional)
Add safe IP addresses:
```json
{
  "ips": [
    "203.0.113.1",
    "198.51.100.1"
  ]
}
```

### 5.5 Commit Changes
```bash
git add .
git commit -m "Configure data files with authorized emails and redirect URLs"
git push
```

---

## Step 6: Deploy to Cloudflare Workers

### 6.1 Test Locally (Optional)
```bash
npm run dev
```
This starts a local development server at `http://localhost:8787`

### 6.2 Deploy to Production
```bash
npm run deploy
```

### 6.3 Verify Deployment
1. Check the deployment URL provided by Wrangler
2. Test the landing page functionality
3. Verify Turnstile integration
4. Test email validation and redirection

---

## Step 7: Configure Custom Domain (Optional)

### 7.1 Add Domain to Cloudflare
1. Go to Cloudflare Dashboard
2. Click "Add a Site"
3. Enter your domain name
4. Choose the free plan
5. Update your domain's nameservers as instructed

### 7.2 Configure Worker Route
1. In Cloudflare Dashboard, go to "Workers & Pages"
2. Select your worker
3. Go to "Settings" → "Triggers"
4. Add a custom domain route

---

## Step 8: Testing and Monitoring

### 8.1 Test All Features
- ✅ Email input and validation
- ✅ Turnstile challenge
- ✅ Authorized email redirection
- ✅ Unauthorized email blocking
- ✅ Rate limiting (3 attempts per IP)
- ✅ Dark/light mode toggle
- ✅ Multi-language support
- ✅ Accessibility features
- ✅ Mobile responsiveness

### 8.2 Monitor Analytics
- Check Cloudflare Workers analytics
- Monitor KV storage usage
- Review Turnstile analytics

---

## 🔧 Troubleshooting

### Common Issues:

1. **"KV namespace not found"**
   - Ensure KV namespace is created and IDs are correct in `wrangler.toml`

2. **"Turnstile verification failed"**
   - Verify Site Key and Secret Key are correct
   - Check that Turnstile is properly configured in Cloudflare Dashboard

3. **"GitHub JSON files not accessible"**
   - Ensure repository is public
   - Verify GitHub URLs are correct in `worker.js`

4. **"Rate limiting not working"**
   - Check KV namespace configuration
   - Verify KV binding in `wrangler.toml`

### Getting Help:
- Check Cloudflare Workers logs in Dashboard
- Review browser console for frontend errors
- Verify all configuration files are properly formatted

---

## 🎉 Success!

Your secure redirect landing page is now deployed and ready to use! The system includes:

- ✅ Real-time JSON updates from GitHub
- ✅ Persistent KV-based rate limiting
- ✅ Progressive delays with exponential backoff
- ✅ Advanced bot protection (fingerprinting, honeypots)
- ✅ Dark/light mode and multi-language support
- ✅ WCAG-compliant accessibility features
- ✅ Mobile-responsive design

**Your landing page URL:** `https://secure-redirect-landing.YOUR_SUBDOMAIN.workers.dev`

---

## 📝 Next Steps

1. **Customize the UI**: Edit the embedded HTML/CSS/JS in `src/worker.js`
2. **Add more authorized emails**: Update `data/list.json` on GitHub
3. **Add more redirect URLs**: Update `data/url.json` on GitHub
4. **Monitor usage**: Check Cloudflare Workers analytics
5. **Set up custom domain**: Follow Step 7 for professional branding

---

## 🔗 Useful Links

- [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers/)
- [Cloudflare Turnstile Documentation](https://developers.cloudflare.com/turnstile/)
- [Cloudflare KV Documentation](https://developers.cloudflare.com/workers/runtime-apis/kv/)
- [GitHub Raw Content API](https://docs.github.com/en/rest/repos/contents#get-repository-content) 