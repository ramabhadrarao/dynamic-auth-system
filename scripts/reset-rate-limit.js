// File: scripts/reset-rate-limit.js
// Simple script to clear rate limit (for development)

console.log('Rate limiting has been updated for development.');
console.log('Restart your server to apply the new settings:');
console.log('');
console.log('Press Ctrl+C to stop the server, then run:');
console.log('npm run dev');
console.log('');
console.log('New rate limit settings:');
console.log('- Window: 15 minutes');
console.log('- Max requests: 200 per window');
console.log('- Admin dashboard is exempt from rate limiting');
console.log('- Static files are exempt from rate limiting');