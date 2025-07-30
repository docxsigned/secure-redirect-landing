# Deployment Guide

This guide will walk you through deploying your secure redirect landing page to Cloudflare Workers.

## Prerequisites

1. **Cloudflare Account**: Sign up at [cloudflare.com](https://cloudflare.com)
2. **Node.js**: Version 16 or higher
3. **GitHub Account**: For storing configuration files
4. **Wrangler CLI**: Cloudflare Workers deployment tool

## Step 1: Setup Cloudflare Turnstile

1. Go to your [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Navigate to **Security** → **Turnstile**
3. Click **Add Site**
4. Choose **Managed** challenge type
5. Enter your domain (or use a placeholder for testing)
6. Copy your **Site Key** and **Secret Key**

## Step 2: Create GitHub Repository

1. Create a new repository on GitHub
2. Upload the files from the `data/` folder:
   - `list.json` (email whitelist)
   - `url.json` (redirect URLs)
   - `blacklist.txt` (blocked IPs)
   - `whitelist.json` (optional safe IPs)

## Step 3: Configure the Application

### Update Worker Configuration

Edit `src/worker.js` and replace the following:

```javascript
// Line ~156: Replace with your Turnstile secret key
formData.append('secret', 'YOUR_TURNSTILE_SECRET_KEY');

// Lines ~170, ~185, ~200: Replace with your GitHub repository URLs
const response = await fetch('https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/list.json');
const response = await fetch('https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/blacklist.txt');
const response = await fetch('https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/url.json');
```

### Update Frontend Configuration

In the same file, find the HTML template (around line 250) and update:

```html
<div class="cf-turnstile" data-sitekey="YOUR_TURNSTILE_SITE_KEY"></div>
```

And in the JavaScript section (around line 400):

```javascript
sitekey: 'YOUR_TURNSTILE_SITE_KEY',
```

## Step 4: Install Dependencies

```bash
npm install
```

## Step 5: Install Wrangler CLI

```bash
npm install -g wrangler
```

## Step 6: Login to Cloudflare

```bash
wrangler login
```

This will open your browser to authenticate with Cloudflare.

## Step 7: Configure Wrangler

Edit `wrangler.toml` if needed:

```toml
name = "your-worker-name"
main = "src/worker.js"
compatibility_date = "2024-01-01"
```

## Step 8: Test Locally (Optional)

```bash
npm run dev
```

This will start a local development server for testing.

## Step 9: Deploy to Cloudflare Workers

```bash
npm run deploy
```

Or directly with wrangler:

```bash
wrangler deploy
```

## Step 10: Verify Deployment

1. Check the deployment output for your worker URL
2. Visit the URL to test the application
3. Verify that Turnstile loads correctly
4. Test with an authorized email from your `list.json`

## Troubleshooting

### Common Issues

1. **Turnstile not loading**
   - Verify your site key is correct
   - Check that the domain is configured in Turnstile settings

2. **Rate limiting too aggressive**
   - Adjust the `maxAttempts` and `windowMs` values in `checkRateLimit` function

3. **JSON files not found**
   - Verify GitHub repository URLs are correct
   - Ensure files are in the main branch
   - Check file permissions

4. **Deployment fails**
   - Verify Wrangler is logged in
   - Check `wrangler.toml` configuration
   - Ensure all dependencies are installed

### Debug Steps

1. Check Cloudflare Workers logs in the dashboard
2. Use browser developer tools to check for JavaScript errors
3. Verify network requests in browser dev tools
4. Test Turnstile verification separately

## Production Considerations

### Security
- Use environment variables for sensitive keys
- Implement proper logging
- Consider using Cloudflare KV for rate limiting
- Add monitoring and alerting

### Performance
- Enable Cloudflare caching
- Optimize static assets
- Consider using Durable Objects for better rate limiting

### Monitoring
- Set up Cloudflare Analytics
- Monitor worker performance
- Track successful/failed access attempts

## Custom Domain Setup

1. Add a custom domain in Cloudflare
2. Configure DNS records
3. Update Turnstile settings with the custom domain
4. Update any hardcoded URLs in the code

## Environment Variables (Optional)

For better security, use environment variables:

1. Add to `wrangler.toml`:
```toml
[vars]
TURNSTILE_SECRET_KEY = "your-secret-key"
GITHUB_REPO_URL = "https://raw.githubusercontent.com/yourusername/yourrepo/main"
```

2. Update the worker code to use `env.TURNSTILE_SECRET_KEY` and `env.GITHUB_REPO_URL`

## Final Checklist

- [ ] Turnstile site key configured
- [ ] Turnstile secret key configured
- [ ] GitHub repository URLs updated
- [ ] Email whitelist populated
- [ ] Redirect URLs configured
- [ ] Worker deployed successfully
- [ ] Local testing completed
- [ ] Mobile responsiveness verified
- [ ] Security features tested

Your secure redirect landing page is now ready for production use! 