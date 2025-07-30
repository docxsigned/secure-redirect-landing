#!/usr/bin/env node

const readline = require('readline');
const { execSync } = require('child_process');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

console.log('🚀 GitHub Repository Setup Helper\n');

console.log('📋 STEP 1: Create GitHub Repository');
console.log('1. Go to https://github.com');
console.log('2. Click the "+" icon in the top right corner');
console.log('3. Select "New repository"');
console.log('4. Name it: secure-redirect-landing');
console.log('5. Make it PUBLIC (required for Cloudflare to access JSON files)');
console.log('6. Add description: "Secure redirect landing page with Cloudflare Workers"');
console.log('7. DO NOT initialize with README, .gitignore, or license');
console.log('8. Click "Create repository"\n');

console.log('📋 STEP 2: Get Your Repository URL');
console.log('After creating the repository, copy the repository URL.');
console.log('It should look like: https://github.com/YOUR_USERNAME/secure-redirect-landing\n');

rl.question('Enter your GitHub repository URL: ', (repoUrl) => {
  if (!repoUrl.includes('github.com')) {
    console.log('❌ Invalid GitHub URL. Please enter a valid GitHub repository URL.');
    rl.close();
    return;
  }

  console.log('\n🔗 Connecting to GitHub repository...');
  
  try {
    // Add the remote origin
    execSync(`git remote add origin ${repoUrl}`, { stdio: 'inherit' });
    console.log('✅ Remote origin added successfully');
    
    // Set the main branch
    execSync('git branch -M main', { stdio: 'inherit' });
    console.log('✅ Branch set to main');
    
    // Push to GitHub
    console.log('\n📤 Pushing to GitHub...');
    execSync('git push -u origin main', { stdio: 'inherit' });
    console.log('✅ Successfully pushed to GitHub!');
    
    console.log('\n🎉 Your project is now on GitHub!');
    console.log(`Repository URL: ${repoUrl}`);
    console.log('\n📋 Next Steps:');
    console.log('1. Run: npm run setup');
    console.log('2. Get your Turnstile keys from Cloudflare Dashboard');
    console.log('3. Create KV namespace: wrangler kv:namespace create "RATE_LIMIT_KV"');
    console.log('4. Update wrangler.toml with KV IDs');
    console.log('5. Deploy: npm run deploy');
    console.log('\n📖 See GITHUB_DEPLOYMENT_GUIDE.md for detailed instructions');
    
  } catch (error) {
    console.log('❌ Error:', error.message);
    console.log('\n💡 Troubleshooting:');
    console.log('1. Make sure the repository URL is correct');
    console.log('2. Ensure you have write access to the repository');
    console.log('3. Check if you\'re authenticated with GitHub');
    console.log('4. Try: git remote remove origin (if already exists)');
  }
  
  rl.close();
}); 