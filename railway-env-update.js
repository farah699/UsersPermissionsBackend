#!/usr/bin/env node

/**
 * Simple script to help update Railway environment variables
 * Since railway CLI might not be installed, this provides instructions
 */

console.log('🚀 Railway Environment Update Instructions');
console.log('==========================================');
console.log();
console.log('To enable MongoDB connection on Railway:');
console.log();
console.log('1. Go to: https://railway.app/dashboard');
console.log('2. Select your project: users-permissions-backend-production');
console.log('3. Go to the Variables tab');
console.log('4. Remove the SKIP_MONGODB variable (if it exists)');
console.log('5. Ensure these variables are set:');
console.log('   - MONGODB_URI: your MongoDB Atlas connection string');
console.log('   - JWT_SECRET: your JWT secret key');
console.log('   - JWT_REFRESH_SECRET: your JWT refresh secret key');
console.log('   - NODE_ENV: production');
console.log('   - CORS_ORIGIN: https://users-permissions-frontend-seven.vercel.app');
console.log();
console.log('6. The app will automatically redeploy after variable changes');
console.log();
console.log('Current MongoDB URI pattern should look like:');
console.log('mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/users_permissions_db?retryWrites=true&w=majority');
console.log();
console.log('✅ After updating, test the endpoint:');
console.log('GET https://users-permissions-backend-production.up.railway.app/health');
console.log();