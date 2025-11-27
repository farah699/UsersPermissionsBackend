import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { User } from '../models/User';
import { AuditLog } from '../models/AuditLog';
import { authenticate } from '../middleware/auth';
import { 
  loginSchema, 
  refreshTokenSchema, 
  forgotPasswordSchema, 
  resetPasswordSchema,
  changePasswordSchema,
  signupSchema
} from '../validation/schemas';

const router = express.Router();

/**
 * @swagger
 * /api/auth/signup:
 *   post:
 *     summary: User registration
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *               - confirmPassword
 *               - firstName
 *               - lastName
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: User email address
 *               password:
 *                 type: string
 *                 minLength: 8
 *                 description: User password (min 8 chars, must contain uppercase, lowercase, number, special char)
 *               confirmPassword:
 *                 type: string
 *                 description: Password confirmation
 *               firstName:
 *                 type: string
 *                 minLength: 2
 *                 maxLength: 50
 *                 description: User first name
 *               lastName:
 *                 type: string
 *                 minLength: 2
 *                 maxLength: 50
 *                 description: User last name
 *     responses:
 *       201:
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       $ref: '#/components/schemas/User'
 *                     accessToken:
 *                       type: string
 *                     refreshToken:
 *                       type: string
 *       400:
 *         description: Validation error or user already exists
 *       500:
 *         description: Internal server error
 */
router.post('/signup', async (req: Request, res: Response): Promise<void> => {
  try {
    // Validate request body
    const { error, value } = signupSchema.validate(req.body);
    if (error) {
      res.status(400).json({
        success: false,
        message: 'Validation error',
        errors: error.details
      });
      return;
    }

    const { email, password, confirmPassword, firstName, lastName } = value;

    // Check if passwords match
    if (password !== confirmPassword) {
      res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
      return;
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.status(400).json({
        success: false,
        message: 'User with this email already exists'
      });
      return;
    }

    // Get default role (User role)
    const defaultRole = await require('../models/Role').Role.findOne({ name: 'User' });
    if (!defaultRole) {
      // If no default role exists, create user without roles
      console.warn('Default "User" role not found. Creating user without roles.');
    }

    // Generate email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const hashedVerificationToken = crypto
      .createHash('sha256')
      .update(verificationToken)
      .digest('hex');

    // Create new user
    const newUser = await User.create({
      email,
      password,
      firstName,
      lastName,
      roles: defaultRole ? [defaultRole._id] : [],
      isActive: true,
      isEmailVerified: false, // Email verification required
      emailVerificationToken: hashedVerificationToken,
      emailVerificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
    });

    // Generate tokens
    const accessToken = newUser.generateAccessToken();
    const refreshToken = newUser.generateRefreshToken();

    // Save refresh token
    newUser.refreshTokens.push(refreshToken);
    await newUser.save();

    // Send verification email
    const { emailService } = await import('../services/emailService');
    const emailSent = await emailService.sendEmailVerification({
      userName: `${newUser.firstName} ${newUser.lastName}`,
      userEmail: newUser.email,
      verificationToken: verificationToken, // Use original token, not hashed
      verificationUrl: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email?token=${verificationToken}`
    });

    // Create audit log
    await AuditLog.createLog({
      action: 'create',
      resource: 'user',
      resourceId: newUser._id.toString(),
      userId: newUser._id,
      userEmail: newUser.email,
      metadata: { action: 'signup', emailVerificationSent: emailSent },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Populate user roles for response
    await newUser.populate('roles');

    res.status(201).json({
      success: true,
      message: emailSent 
        ? 'Account created successfully! Please check your email to verify your account.'
        : 'Account created successfully! Email verification will be sent shortly.',
      data: {
        user: newUser,
        accessToken,
        refreshToken
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create account'
    });
  }
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: User login
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       $ref: '#/components/schemas/User'
 *                     accessToken:
 *                       type: string
 *                     refreshToken:
 *                       type: string
 *       401:
 *         description: Invalid credentials
 */
router.post('/login', async (req: Request, res: Response): Promise<void> => {
  try {
    // Validate request body
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      res.status(400).json({
        success: false,
        message: error.details[0].message
      });
      return;
    }

    const { email, password } = value;

    // Find user and include password for comparison
    const user = await User.findOne({ email }).select('+password');

    if (!user || !user.isActive) {
      res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
      return;
    }

    // Check password
    const isPasswordValid = await user.comparePassword(password);

    if (!isPasswordValid) {
      res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
      return;
    }

    // Generate tokens
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    // Save refresh token to user
    if (!user.refreshTokens) {
      user.refreshTokens = [];
    }
    user.refreshTokens.push(refreshToken);
    user.lastLogin = new Date();
    await user.save();

    // Create audit log
    await AuditLog.createLog({
      action: 'login',
      resource: 'auth',
      resourceId: user._id.toString(),
      userId: user._id,
      userEmail: user.email,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Remove password from response
    const userResponse = user.toJSON();

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: userResponse,
        accessToken,
        refreshToken
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed'
    });
  }
});

/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Refresh access token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 *       401:
 *         description: Invalid refresh token
 */
router.post('/refresh', async (req: Request, res: Response): Promise<void> => {
  try {
    const { error, value } = refreshTokenSchema.validate(req.body);
    if (error) {
      res.status(400).json({
        success: false,
        message: error.details[0].message
      });
      return;
    }

    const { refreshToken } = value;

    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET!) as any;
      
      const user = await User.findById(decoded.id);

      if (!user || !user.isActive || !user.refreshTokens || !user.refreshTokens.includes(refreshToken)) {
        res.status(401).json({
          success: false,
          message: 'Invalid refresh token'
        });
        return;
      }

      // Generate new access token
      const newAccessToken = user.generateAccessToken();

      res.json({
        success: true,
        message: 'Token refreshed successfully',
        data: {
          accessToken: newAccessToken
        }
      });
    } catch (jwtError) {
      res.status(401).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      message: 'Token refresh failed'
    });
  }
});

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: User logout
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               refreshToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: Logout successful
 */
router.post('/logout', authenticate, async (req: Request, res: Response): Promise<void> => {
  try {
    const { refreshToken } = req.body;

    if (refreshToken && req.user && req.user.refreshTokens) {
      // Remove specific refresh token
      req.user.refreshTokens = req.user.refreshTokens.filter(token => token !== refreshToken);
      await req.user.save();
    }

    // Create audit log
    if (req.user) {
      await AuditLog.createLog({
        action: 'logout',
        resource: 'auth',
        resourceId: req.user._id.toString(),
        userId: req.user._id,
        userEmail: req.user.email,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });
    }

    res.json({
      success: true,
      message: 'Logout successful'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Logout failed'
    });
  }
});

/**
 * @swagger
 * /api/auth/logout-all:
 *   post:
 *     summary: Logout from all devices
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logged out from all devices
 */
router.post('/logout-all', authenticate, async (req: Request, res: Response): Promise<void> => {
  try {
    if (req.user) {
      // Clear all refresh tokens
      req.user.refreshTokens = [];
      await req.user.save();

      // Create audit log
      await AuditLog.createLog({
        action: 'logout',
        resource: 'auth',
        resourceId: req.user._id.toString(),
        userId: req.user._id,
        userEmail: req.user.email,
        metadata: { type: 'logout_all_devices' },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });
    }

    res.json({
      success: true,
      message: 'Logged out from all devices'
    });
  } catch (error) {
    console.error('Logout all error:', error);
    res.status(500).json({
      success: false,
      message: 'Logout from all devices failed'
    });
  }
});

/**
 * @swagger
 * /api/auth/me:
 *   get:
 *     summary: Get current user profile
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Current user profile
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   $ref: '#/components/schemas/User'
 */
router.get('/me', authenticate, async (req: Request, res: Response): Promise<void> => {
  try {
    res.json({
      success: true,
      data: req.user
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get profile'
    });
  }
});

/**
 * @swagger
 * /api/auth/change-password:
 *   post:
 *     summary: Change user password
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *               newPassword:
 *                 type: string
 *                 minLength: 8
 *     responses:
 *       200:
 *         description: Password changed successfully
 *       400:
 *         description: Invalid input or current password incorrect
 */
router.post('/change-password', authenticate, async (req: Request, res: Response): Promise<void> => {
  try {
    const { error, value } = changePasswordSchema.validate(req.body);
    if (error) {
      res.status(400).json({
        success: false,
        message: error.details[0].message
      });
      return;
    }

    const { currentPassword, newPassword } = value;

    if (!req.user) {
      res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
      return;
    }

    // Get user with password field
    const user = await User.findById(req.user._id).select('+password');

    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found'
      });
      return;
    }

    // Verify current password
    const isCurrentPasswordValid = await user.comparePassword(currentPassword);

    if (!isCurrentPasswordValid) {
      res.status(400).json({
        success: false,
        message: 'Current password is incorrect'
      });
      return;
    }

    // Update password
    user.password = newPassword;
    
    // Clear all refresh tokens to force re-login on all devices
    user.refreshTokens = [];
    
    await user.save();

    // Create audit log
    await AuditLog.createLog({
      action: 'update',
      resource: 'user',
      resourceId: user._id.toString(),
      userId: user._id,
      userEmail: user.email,
      metadata: { action: 'password_change' },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: 'Password changed successfully. Please login again.'
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to change password'
    });
  }
});

/**
 * @swagger
 * /api/auth/forgot-password:
 *   post:
 *     summary: Request password reset
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *     responses:
 *       200:
 *         description: Password reset email sent (if email exists)
 */
router.post('/forgot-password', async (req: Request, res: Response): Promise<void> => {
  try {
    const { error, value } = forgotPasswordSchema.validate(req.body);
    if (error) {
      res.status(400).json({
        success: false,
        message: error.details[0].message
      });
      return;
    }

    const { email } = value;

    const user = await User.findOne({ email });

    // Always return success to prevent email enumeration
    if (!user) {
      res.json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent.'
      });
      return;
    }

    // Generate password reset token
    const resetToken = user.generatePasswordResetToken();
    await user.save();

    // In a real application, you would send an email here
    // For this demo, we'll just log the token
    console.log('Password reset token for', email, ':', resetToken);

    // Create audit log
    await AuditLog.createLog({
      action: 'read',
      resource: 'auth',
      resourceId: user._id.toString(),
      userId: user._id,
      userEmail: user.email,
      metadata: { action: 'password_reset_request' },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent.',
      ...(process.env.NODE_ENV === 'development' && { resetToken }) // Only in development
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process password reset request'
    });
  }
});

/**
 * @swagger
 * /api/auth/reset-password:
 *   post:
 *     summary: Reset password with token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *               - password
 *             properties:
 *               token:
 *                 type: string
 *               password:
 *                 type: string
 *                 minLength: 8
 *     responses:
 *       200:
 *         description: Password reset successful
 *       400:
 *         description: Invalid or expired token
 */
router.post('/reset-password', async (req: Request, res: Response): Promise<void> => {
  try {
    const { error, value } = resetPasswordSchema.validate(req.body);
    if (error) {
      res.status(400).json({
        success: false,
        message: error.details[0].message
      });
      return;
    }

    const { token, password } = value;

    // Hash the token to compare with stored hash
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: new Date() }
    });

    if (!user) {
      res.status(400).json({
        success: false,
        message: 'Invalid or expired password reset token'
      });
      return;
    }

    // Update password
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.refreshTokens = []; // Clear all refresh tokens

    await user.save();

    // Create audit log
    await AuditLog.createLog({
      action: 'update',
      resource: 'user',
      resourceId: user._id.toString(),
      userId: user._id,
      userEmail: user.email,
      metadata: { action: 'password_reset_complete' },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: 'Password reset successful. Please login with your new password.'
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reset password'
    });
  }
});

/**
 * @swagger
 * /api/auth/change-password:
 *   post:
 *     summary: Change user password
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *                 description: Current password
 *               newPassword:
 *                 type: string
 *                 description: New password (min 8 chars)
 *               confirmPassword:
 *                 type: string
 *                 description: Confirm new password
 *     responses:
 *       200:
 *         description: Password changed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     emailSent:
 *                       type: boolean
 *       400:
 *         description: Validation error or incorrect current password
 *       401:
 *         description: Unauthorized - invalid token
 *       500:
 *         description: Internal server error
 */
router.post('/change-password', authenticate, async (req: Request, res: Response) => {
  try {
    const { error } = changePasswordSchema.validate(req.body);
    if (error) {
      res.status(400).json({
        success: false,
        message: 'Validation error',
        errors: error.details
      });
      return;
    }

    const { currentPassword, newPassword, confirmPassword } = req.body;
    const userId = (req as any).user.id;

    // Get user with password
    const user = await User.findById(userId).select('+password');
    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found'
      });
      return;
    }

    // Verify current password
    const isCurrentPasswordValid = await user.comparePassword(currentPassword);
    if (!isCurrentPasswordValid) {
      res.status(400).json({
        success: false,
        message: 'Current password is incorrect'
      });
      return;
    }

    // Check if new password is different from current
    const isSamePassword = await user.comparePassword(newPassword);
    if (isSamePassword) {
      res.status(400).json({
        success: false,
        message: 'New password must be different from current password'
      });
      return;
    }

    // Validate password confirmation
    if (newPassword !== confirmPassword) {
      res.status(400).json({
        success: false,
        message: 'Password confirmation does not match'
      });
      return;
    }

    // Update password
    user.password = newPassword;
    // Clear all refresh tokens to force re-login on all devices
    user.refreshTokens = [];
    await user.save();

    // Create audit log
    await AuditLog.createLog({
      action: 'update',
      resource: 'user',
      resourceId: user._id.toString(),
      userId: user._id,
      userEmail: user.email,
      metadata: { action: 'password_change', changedBy: 'self' },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Send email notification
    const { emailService } = await import('../services/emailService');
    const emailSent = await emailService.sendPasswordChangeNotification({
      userName: `${user.firstName} ${user.lastName}`,
      userEmail: user.email,
      changedBy: `${user.firstName} ${user.lastName} (self)`,
      timestamp: new Date(),
      ipAddress: req.ip
    });

    res.json({
      success: true,
      message: 'Password changed successfully. Please login again with your new password.',
      data: {
        emailSent
      }
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to change password'
    });
  }
});

/**
 * @swagger
 * /api/auth/verify-email:
 *   post:
 *     summary: Verify user email
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *             properties:
 *               token:
 *                 type: string
 *                 description: Email verification token
 *     responses:
 *       200:
 *         description: Email verified successfully
 *       400:
 *         description: Invalid or expired token
 */
router.post('/verify-email', async (req: Request, res: Response): Promise<void> => {
  try {
    const { token } = req.body;

    if (!token) {
      res.status(400).json({
        success: false,
        message: 'Verification token is required'
      });
      return;
    }

    // Hash the token to compare with stored hash
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    // Find user with this token
    const user = await User.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationExpires: { $gt: new Date() }
    });

    if (!user) {
      res.status(400).json({
        success: false,
        message: 'Invalid or expired verification token'
      });
      return;
    }

    // Update user
    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    // Create audit log
    await AuditLog.createLog({
      action: 'update',
      resource: 'user',
      resourceId: user._id.toString(),
      userId: user._id,
      userEmail: user.email,
      metadata: { action: 'email_verification_completed' },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: 'Email verified successfully! You can now use all features.'
    });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify email'
    });
  }
});

/**
 * @swagger
 * /api/auth/forgot-password:
 *   post:
 *     summary: Request password reset
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: User's email address
 *     responses:
 *       200:
 *         description: Password reset email sent
 *       404:
 *         description: User not found
 */
router.post('/forgot-password', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email } = req.body;

    if (!email) {
      res.status(400).json({
        success: false,
        message: 'Email is required'
      });
      return;
    }

    // Find user by email
    const user = await User.findOne({ email });

    // Always return success for security (don't reveal if email exists)
    if (!user) {
      res.json({
        success: true,
        message: 'If an account with that email exists, we\'ve sent password reset instructions.'
      });
      return;
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    // Set token and expiry (1 hour)
    user.passwordResetToken = hashedToken;
    user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    await user.save();

    // Send reset email
    try {
      await emailService.sendPasswordResetNotification(user.email, user.firstName, resetToken);
      
      // Create audit log
      await AuditLog.createLog({
        action: 'create',
        resource: 'auth',
        resourceId: user._id.toString(),
        userId: user._id,
        userEmail: user.email,
        metadata: { action: 'password_reset_requested' },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });
    } catch (emailError) {
      console.error('Failed to send password reset email:', emailError);
      // Don't fail the request if email fails, for security
    }

    res.json({
      success: true,
      message: 'If an account with that email exists, we\'ve sent password reset instructions.'
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process password reset request'
    });
  }
});

/**
 * @swagger
 * /api/auth/reset-password:
 *   post:
 *     summary: Reset password with token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *               - password
 *             properties:
 *               token:
 *                 type: string
 *                 description: Password reset token
 *               password:
 *                 type: string
 *                 minLength: 8
 *                 description: New password
 *     responses:
 *       200:
 *         description: Password reset successfully
 *       400:
 *         description: Invalid or expired token
 */
router.post('/reset-password', async (req: Request, res: Response): Promise<void> => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      res.status(400).json({
        success: false,
        message: 'Token and password are required'
      });
      return;
    }

    // Validate password strength
    if (password.length < 8) {
      res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long'
      });
      return;
    }

    // Hash the token to compare with stored hash
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Find user with this token
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: new Date() }
    });

    if (!user) {
      res.status(400).json({
        success: false,
        message: 'Invalid or expired reset token'
      });
      return;
    }

    // Hash new password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Update user password and clear reset token
    user.password = hashedPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.passwordChangedAt = new Date();
    await user.save();

    // Invalidate all existing sessions by incrementing tokenVersion
    user.tokenVersion += 1;
    await user.save();

    // Create audit log
    await AuditLog.createLog({
      action: 'update',
      resource: 'user',
      resourceId: user._id.toString(),
      userId: user._id,
      userEmail: user.email,
      metadata: { action: 'password_reset_completed' },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: 'Password reset successfully! You can now sign in with your new password.'
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reset password'
    });
  }
});

export default router;