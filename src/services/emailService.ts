import nodemailer from 'nodemailer';
import { AuditLog } from '../models/AuditLog';

interface EmailOptions {
  to: string;
  subject: string;
  text?: string;
  html?: string;
}

interface PasswordChangeEmailData {
  userName: string;
  userEmail: string;
  changedBy: string;
  timestamp: Date;
  ipAddress?: string;
}

interface EmailVerificationData {
  userName: string;
  userEmail: string;
  verificationToken: string;
  verificationUrl: string;
}

class EmailService {
  private transporter: nodemailer.Transporter;
  
  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    // Verify connection configuration
    this.verifyConnection();
  }

  private async verifyConnection(): Promise<void> {
    try {
      if (process.env.SMTP_USER && process.env.SMTP_PASS) {
        await this.transporter.verify();
        console.log('📧 Email service is ready');
      } else {
        console.log('⚠️ Email service not configured (SMTP credentials missing)');
      }
    } catch (error) {
      console.error('❌ Email service connection failed:', error);
    }
  }

  private async sendEmail(options: EmailOptions): Promise<boolean> {
    try {
      // If no SMTP credentials, log instead of sending
      if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
        console.log('📧 [EMAIL SIMULATION] Would send email:', {
          to: options.to,
          subject: options.subject,
          text: options.text?.substring(0, 100) + '...'
        });
        return true;
      }

      const mailOptions = {
        from: process.env.EMAIL_FROM || process.env.SMTP_USER,
        to: options.to,
        subject: options.subject,
        text: options.text,
        html: options.html,
      };

      const info = await this.transporter.sendMail(mailOptions);
      console.log('📧 Email sent successfully:', info.messageId);
      return true;
    } catch (error) {
      console.error('❌ Failed to send email:', error);
      return false;
    }
  }

  async sendPasswordChangeNotification(data: PasswordChangeEmailData): Promise<boolean> {
    const subject = '🔐 Password Changed - Security Alert';
    
    const text = `
Hello ${data.userName},

Your account password has been successfully changed.

Details:
- Account: ${data.userEmail}
- Changed by: ${data.changedBy}
- Time: ${data.timestamp.toLocaleString()}
- IP Address: ${data.ipAddress || 'Unknown'}

If you did not make this change, please contact your administrator immediately.

Best regards,
OpusLab Security Team
    `;

    const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .alert { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .details { background-color: #f8f9fa; padding: 15px; border-radius: 4px; margin: 15px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 12px; color: #6c757d; }
        .security-icon { color: #28a745; font-size: 24px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2><span class="security-icon">🔐</span> Password Changed Successfully</h2>
        </div>
        
        <p>Hello <strong>${data.userName}</strong>,</p>
        
        <div class="alert">
            <strong>Security Alert:</strong> Your account password has been successfully changed.
        </div>
        
        <div class="details">
            <h3>Change Details:</h3>
            <ul>
                <li><strong>Account:</strong> ${data.userEmail}</li>
                <li><strong>Changed by:</strong> ${data.changedBy}</li>
                <li><strong>Time:</strong> ${data.timestamp.toLocaleString()}</li>
                <li><strong>IP Address:</strong> ${data.ipAddress || 'Unknown'}</li>
            </ul>
        </div>
        
        <p><strong>If you did not make this change, please contact your administrator immediately.</strong></p>
        
        <p>For your security, we recommend:</p>
        <ul>
            <li>Using strong, unique passwords</li>
            <li>Enabling two-factor authentication when available</li>
            <li>Regularly reviewing your account activity</li>
        </ul>
        
        <div class="footer">
            <p>Best regards,<br>
            <strong>OpusLab Security Team</strong></p>
            <p><em>This is an automated security notification. Please do not reply to this email.</em></p>
        </div>
    </div>
</body>
</html>
    `;

    return await this.sendEmail({
      to: data.userEmail,
      subject,
      text,
      html
    });
  }

  async sendPasswordResetNotification(userEmail: string, userName: string, resetToken: string): Promise<boolean> {
    const subject = '🔑 Password Reset Request';
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
    
    const text = `
Hello ${userName},

You have requested to reset your password. Please click the link below to reset your password:

${resetUrl}

This link will expire in 10 minutes for security reasons.

If you did not request this password reset, please ignore this email.

Best regards,
OpusLab Support Team
    `;

    const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .button { display: inline-block; background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .warning { background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 12px; color: #6c757d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🔑 Password Reset Request</h2>
        </div>
        
        <p>Hello <strong>${userName}</strong>,</p>
        
        <p>You have requested to reset your password. Click the button below to proceed:</p>
        
        <a href="${resetUrl}" class="button">Reset Password</a>
        
        <div class="warning">
            <strong>Security Notice:</strong> This link will expire in 10 minutes for security reasons.
        </div>
        
        <p>If you did not request this password reset, please ignore this email.</p>
        
        <div class="footer">
            <p>Best regards,<br>
            <strong>OpusLab Support Team</strong></p>
            <p><em>This is an automated message. Please do not reply to this email.</em></p>
        </div>
    </div>
</body>
</html>
    `;

    return await this.sendEmail({
      to: userEmail,
      subject,
      text,
      html
    });
  }

  async sendEmailVerification(data: EmailVerificationData): Promise<boolean> {
    const subject = '✉️ Verify Your Email Address';
    
    const text = `
Hello ${data.userName},

Welcome to OpusLab! Please verify your email address to complete your account setup.

Click the link below to verify your email:
${data.verificationUrl}

This link will expire in 24 hours for security reasons.

If you didn't create this account, please ignore this email.

Best regards,
OpusLab Team
    `;

    const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; text-align: center; }
        .welcome-icon { color: #28a745; font-size: 48px; }
        .button { display: inline-block; background-color: #007bff; color: white; padding: 16px 32px; text-decoration: none; border-radius: 8px; margin: 20px 0; font-weight: bold; }
        .button:hover { background-color: #0056b3; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 12px; color: #6c757d; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="welcome-icon">🎉</div>
            <h1>Welcome to OpusLab!</h1>
            <p>Thank you for joining our platform</p>
        </div>
        
        <p>Hello <strong>${data.userName}</strong>,</p>
        
        <p>Welcome to OpusLab! We're excited to have you on board.</p>
        
        <p>To complete your account setup and start using all features, please verify your email address by clicking the button below:</p>
        
        <div style="text-align: center;">
            <a href="${data.verificationUrl}" class="button">Verify Email Address</a>
        </div>
        
        <div class="warning">
            <strong>Important:</strong> This verification link will expire in 24 hours for security reasons.
        </div>
        
        <p>If the button above doesn't work, you can copy and paste this link into your browser:</p>
        <p style="word-break: break-all; background-color: #f8f9fa; padding: 10px; border-radius: 4px;">
            ${data.verificationUrl}
        </p>
        
        <p>If you didn't create this account, please ignore this email.</p>
        
        <div class="footer">
            <p>Best regards,<br>
            <strong>OpusLab Team</strong></p>
            <p><em>This is an automated message. Please do not reply to this email.</em></p>
        </div>
    </div>
</body>
</html>
    `;

    return await this.sendEmail({
      to: data.userEmail,
      subject,
      text,
      html
    });
  }

  async testConnection(): Promise<{ success: boolean; message: string }> {
    try {
      if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
        return {
          success: false,
          message: 'SMTP credentials not configured'
        };
      }

      await this.transporter.verify();
      return {
        success: true,
        message: 'Email service connection successful'
      };
    } catch (error) {
      return {
        success: false,
        message: `Email service connection failed: ${error}`
      };
    }
  }
}

// Export singleton instance
export const emailService = new EmailService();
export default EmailService;