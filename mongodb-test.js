#!/usr/bin/env node

/**
 * MongoDB Atlas Connection Test
 * This script helps verify if your MongoDB Atlas cluster is accessible
 */

const https = require('https');
const dns = require('dns');

console.log('🔍 MongoDB Atlas Connection Test');
console.log('================================');

// Test DNS resolution for MongoDB Atlas
const atlasHostname = 'cluster0.zn8e8.mongodb.net'; // Update this to match your cluster

console.log(`\n1. Testing DNS resolution for ${atlasHostname}...`);

dns.lookup(atlasHostname, (err, address, family) => {
  if (err) {
    console.log('❌ DNS resolution failed:', err.message);
    console.log('   This could be a Railway networking issue');
  } else {
    console.log(`✅ DNS resolved: ${address} (IPv${family})`);
  }
});

console.log('\n2. MongoDB Atlas Environment Variables Checklist:');
console.log('   ✅ MONGODB_URI should include:');
console.log('      - Username and password');
console.log('      - Cluster hostname (cluster0.xxxxx.mongodb.net)');
console.log('      - Database name (users_permissions_db)');
console.log('      - retryWrites=true&w=majority parameters');
console.log('\n   Example:');
console.log('   mongodb+srv://username:password@cluster0.xxxxx.mongodb.net/users_permissions_db?retryWrites=true&w=majority');

console.log('\n3. MongoDB Atlas Network Access:');
console.log('   ✅ Check if "Allow access from anywhere" (0.0.0.0/0) is enabled');
console.log('   ✅ Or add Railway\'s IP ranges to the whitelist');

console.log('\n4. Railway Environment Variables to Check:');
console.log('   ✅ MONGODB_URI - your connection string');
console.log('   ✅ NODE_ENV - set to "production"');
console.log('   ❌ SKIP_MONGODB - remove this variable completely');

console.log('\n5. Next Steps:');
console.log('   1. Go to Railway dashboard');
console.log('   2. Check the deployment logs for MongoDB connection errors');
console.log('   3. Verify the MONGODB_URI environment variable');
console.log('   4. Ensure MongoDB Atlas allows connections from anywhere');

console.log('\nIf all settings look correct but connection still fails,');
console.log('try redeploying the Railway service after making changes.');