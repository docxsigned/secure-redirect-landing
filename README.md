# Secure Redirect Landing Page

A secure web-based redirect interface with Cloudflare Turnstile protection, email validation, and IP-based rate limiting.

## 🚀 Features

- **Modern UI**: Clean, responsive design with smooth animations
- **Cloudflare Turnstile**: Bot protection and verification
- **Email Validation**: Checks against whitelist stored in GitHub
- **Enhanced Rate Limiting**: Persistent KV storage with exponential backoff
- **Real-time Updates**: JSON configuration updates without redeployment
- **Advanced Bot Protection**: Browser fingerprinting, honeypot fields, pattern analysis
- **Dark/Light Mode**: Theme toggle with auto-detection
- **Multi-language Support**: English, Spanish, French, German
- **Accessibility Features**: WCAG compliance, font size controls, high contrast
- **IP Blacklisting**: Block specific IP addresses
- **Random Redirects**: Selects random URL from configured list
- **Mobile Responsive**: Works perfectly on all devices
- **Security Features**: Disabled right-click, dev tools protection

## 📁 Project Structure

```
├── src/
│   └── worker.js          # Cloudflare Worker main file
├── data/                  # JSON files for GitHub storage
│   ├── list.json         # Authorized email whitelist
│   ├── url.json          # Redirect URLs
│   ├── blacklist.txt     # Blocked IP addresses
│   └── whitelist.json    # Safe IP addresses (optional)
├── package.json          # Project dependencies
├── wrangler.toml         # Cloudflare Workers configuration
└── README.md            # This file
```

## 🛠️ Setup Instructions

### 1. Prerequisites

- Node.js (v16 or higher)
- Cloudflare account
- GitHub account

### 2. Install Dependencies

```bash
npm install
```

### 3. Cloudflare Turnstile Setup

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Navigate to **Security** → **Turnstile**
3. Create a new site key
4. Note down your **Site Key** and **Secret Key**

### 4. Configure the Application

#### Update Worker Configuration

Edit `src/worker.js` and replace the following placeholders:

```javascript
// Line 156: Replace with your Turnstile secret key
formData.append('secret', 'YOUR_TURNSTILE_SECRET_KEY');

// Lines 170, 185, 200: Replace with your GitHub repository URLs
const response = await fetch('https://raw.githubusercontent.com/yourusername/yourrepo/main/list.json');
const response = await fetch('https://raw.githubusercontent.com/yourusername/yourrepo/main/blacklist.txt');
const response = await fetch('https://raw.githubusercontent.com/yourusername/yourrepo/main/url.json');
```

#### Update Frontend Configuration

Edit the HTML template in `src/worker.js` (around line 250):

```html
<!-- Replace YOUR_TURNSTILE_SITE_KEY with your actual site key -->
<div class="cf-turnstile" data-sitekey="YOUR_TURNSTILE_SITE_KEY"></div>
```

And in the JavaScript section (around line 400):

```javascript
// Replace YOUR_TURNSTILE_SITE_KEY with your actual site key
sitekey: 'YOUR_TURNSTILE_SITE_KEY',
```

### 5. GitHub Repository Setup

1. Create a new GitHub repository
2. Upload the JSON files from the `data/` folder to your repository
3. Update the fetch URLs in `src/worker.js` to point to your repository

### 6. Deploy to Cloudflare Workers

#### Install Wrangler CLI

```bash
npm install -g wrangler
```

#### Login to Cloudflare

```bash
wrangler login
```

#### Deploy the Worker

```bash
npm run deploy
```

## 📋 Configuration Files

### list.json (Email Whitelist)
```json
{
  "emails": [
    "user1@example.com",
    "user2@example.com",
    "admin@company.com"
  ]
}
```

### url.json (Redirect URLs)
```json
{
  "urls": [
    "https://www.example.com/redir/index.html",
    "https://secure.company.com/portal"
  ]
}
```

### blacklist.txt (Blocked IPs)
```
192.168.1.100
10.0.0.50
# One IP per line
```

### whitelist.json (Safe IPs - Optional)
```json
{
  "ips": [
    "203.0.113.1",
    "198.51.100.1"
  ]
}
```

## 🔧 Customization

### Styling
- Edit the CSS in the `serveStaticFile` function in `src/worker.js`
- Modify colors, fonts, and animations as needed

### Security
- Adjust rate limiting parameters in `checkRateLimit` function
- Modify IP blocking logic
- Add additional validation rules

### Functionality
- Add more validation steps
- Implement logging to external services
- Add analytics tracking

## 🚀 Usage

1. Users visit your Cloudflare Worker URL
2. They see a modern email input form
3. Turnstile verification appears
4. After successful verification, email is validated
5. If authorized, user is redirected to a random URL with email appended

## 🔒 Security Features

- **Turnstile Protection**: Prevents bot access
- **Rate Limiting**: 3 attempts per IP per 15 minutes
- **IP Blacklisting**: Block specific IP addresses
- **Email Validation**: Only authorized emails can access
- **Input Sanitization**: Prevents XSS attacks
- **CORS Protection**: Proper CORS headers
- **Dev Tools Protection**: Basic client-side protection

## 📱 Mobile Responsive

The interface is fully responsive and works on:
- Desktop computers
- Tablets
- Mobile phones
- All modern browsers

## 🐛 Troubleshooting

### Common Issues

1. **Turnstile not loading**: Check your site key configuration
2. **Rate limiting too strict**: Adjust the `maxAttempts` and `windowMs` values
3. **JSON files not found**: Verify GitHub repository URLs
4. **Deployment fails**: Check Wrangler configuration

### Debug Mode

Enable console logging by uncommenting debug statements in the worker code.

## 📄 License

MIT License - feel free to use and modify as needed.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📞 Support

For issues and questions:
- Check the troubleshooting section
- Review Cloudflare Workers documentation
- Verify Turnstile configuration

---

**Note**: Remember to replace all placeholder values with your actual configuration before deploying! 