#!/usr/bin/env node

/**
 * Setup script for Secure Redirect Landing Page
 * This script helps configure the application with your own values
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(prompt) {
  return new Promise((resolve) => {
    rl.question(prompt, resolve);
  });
}

async function setup() {
  console.log('🚀 Secure Redirect Landing Page Setup\n');
  console.log('This script will help you configure the application.\n');

  try {
    // Get configuration values
    const turnstileSiteKey = await question('Enter your Cloudflare Turnstile Site Key: ');
    const turnstileSecretKey = await question('Enter your Cloudflare Turnstile Secret Key: ');
    const githubUsername = await question('Enter your GitHub username: ');
    const githubRepo = await question('Enter your GitHub repository name: ');

    console.log('\n📝 Configuration Summary:');
    console.log(`- Turnstile Site Key: ${turnstileSiteKey}`);
    console.log(`- Turnstile Secret Key: ${turnstileSecretKey.substring(0, 8)}...`);
    console.log(`- GitHub Repository: ${githubUsername}/${githubRepo}`);

    const confirm = await question('\nIs this correct? (y/N): ');
    if (confirm.toLowerCase() !== 'y') {
      console.log('Setup cancelled.');
      process.exit(0);
    }

    // Read the worker file
    const workerPath = path.join(__dirname, 'src', 'worker.js');
    let workerContent = fs.readFileSync(workerPath, 'utf8');

    // Replace placeholders
    workerContent = workerContent.replace(/YOUR_TURNSTILE_SECRET_KEY/g, turnstileSecretKey);
    workerContent = workerContent.replace(/YOUR_TURNSTILE_SITE_KEY/g, turnstileSiteKey);
    workerContent = workerContent.replace(/yourusername\/yourrepo/g, `${githubUsername}/${githubRepo}`);

    // Write the updated file
    fs.writeFileSync(workerPath, workerContent);

    console.log('\n✅ Configuration updated successfully!');
    console.log('\n📋 Next steps:');
    console.log('1. Create a Cloudflare KV namespace for rate limiting');
    console.log('2. Update the KV namespace IDs in wrangler.toml');
    console.log('3. Upload the files from the data/ folder to your GitHub repository');
    console.log('4. Run: npm install');
    console.log('5. Run: npm install -g wrangler');
    console.log('6. Run: wrangler login');
    console.log('7. Run: npm run deploy');
    console.log('\n📖 See README.md and DEPLOYMENT.md for detailed instructions.');
    console.log('\n🔧 New Features Added:');
    console.log('- Enhanced rate limiting with KV storage');
    console.log('- Real-time JSON updates from GitHub');
    console.log('- Advanced bot protection with fingerprinting');
    console.log('- Dark/light mode toggle');
    console.log('- Multi-language support (EN, ES, FR, DE)');
    console.log('- Accessibility improvements (WCAG compliant)');

  } catch (error) {
    console.error('❌ Error during setup:', error.message);
    process.exit(1);
  } finally {
    rl.close();
  }
}

// Run setup if this script is executed directly
if (require.main === module) {
  setup();
}

module.exports = { setup }; 