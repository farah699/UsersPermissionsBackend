const nodemailer = require('nodemailer');

async function createTestAccount() {
  try {
    // Créer un compte de test Ethereal
    const testAccount = await nodemailer.createTestAccount();
    
    console.log('🎯 COMPTE EMAIL DE TEST CRÉÉ !');
    console.log('==============================');
    console.log('📧 Email:', testAccount.user);
    console.log('🔑 Mot de passe:', testAccount.pass);
    console.log('🌐 SMTP Host:', testAccount.smtp.host);
    console.log('🔌 SMTP Port:', testAccount.smtp.port);
    console.log('');
    console.log('👇 Copiez ces informations dans votre fichier .env :');
    console.log('==============================');
    console.log(`SMTP_HOST=${testAccount.smtp.host}`);
    console.log(`SMTP_PORT=${testAccount.smtp.port}`);
    console.log(`SMTP_USER=${testAccount.user}`);
    console.log(`SMTP_PASS=${testAccount.pass}`);
    console.log('==============================');
    console.log('');
    console.log('📬 Les emails seront visibles sur: https://ethereal.email');
    console.log('🔍 Utilisez les credentials ci-dessus pour vous connecter');
    
  } catch (error) {
    console.error('❌ Erreur lors de la création du compte test:', error);
  }
}

createTestAccount();