import { User } from '../../models/User';
import { Role } from '../../models/Role';
import { Permission } from '../../models/Permission';
import bcrypt from 'bcryptjs';

describe('User Model Tests', () => {
  let testRole: any;
  let testPermissions: any[];

  beforeEach(async () => {
    // Create test permissions
    testPermissions = await Permission.insertMany([
      {
        name: 'user:read',
        resource: 'user',
        action: 'read',
        description: 'Read user information'
      },
      {
        name: 'user:create',
        resource: 'user',
        action: 'create',
        description: 'Create new users'
      }
    ]);

    // Create test role
    testRole = await Role.create({
      name: 'Test Role',
      description: 'Role for testing',
      permissions: testPermissions.map(p => p._id),
      isActive: true
    });
  });

  describe('User Creation', () => {
    it('should create a valid user', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'TestPassword123!',
        firstName: 'Test',
        lastName: 'User',
        roles: [testRole._id],
        isActive: true,
        isEmailVerified: false
      };

      const user = await User.create(userData);

      expect(user.email).toBe(userData.email);
      expect(user.firstName).toBe(userData.firstName);
      expect(user.lastName).toBe(userData.lastName);
      expect(user.isActive).toBe(true);
      expect(user.isEmailVerified).toBe(false);
      expect(user.roles).toHaveLength(1);
      expect(user.createdAt).toBeDefined();
      expect(user.updatedAt).toBeDefined();
    });

    it('should hash password before saving', async () => {
      const password = 'TestPassword123!';
      const user = await User.create({
        email: 'test@example.com',
        password: password,
        firstName: 'Test',
        lastName: 'User'
      });

      expect(user.password).not.toBe(password);
      expect(user.password).toHaveLength(60); // bcrypt hash length
    });

    it('should require unique email', async () => {
      const userData = {
        email: 'duplicate@example.com',
        password: 'TestPassword123!',
        firstName: 'Test',
        lastName: 'User'
      };

      await User.create(userData);

      await expect(User.create(userData)).rejects.toThrow();
    });

    it('should validate email format', async () => {
      const userData = {
        email: 'invalid-email',
        password: 'TestPassword123!',
        firstName: 'Test',
        lastName: 'User'
      };

      await expect(User.create(userData)).rejects.toThrow();
    });
  });

  describe('User Methods', () => {
    let testUser: any;

    beforeEach(async () => {
      testUser = await User.create({
        email: 'test@example.com',
        password: 'TestPassword123!',
        firstName: 'Test',
        lastName: 'User',
        roles: [testRole._id]
      });
    });

    it('should compare password correctly', async () => {
      const isMatch = await testUser.comparePassword('TestPassword123!');
      expect(isMatch).toBe(true);

      const isNotMatch = await testUser.comparePassword('WrongPassword');
      expect(isNotMatch).toBe(false);
    });

    it('should check permissions correctly', async () => {
      // Populate the user with roles and permissions
      await testUser.populate('roles');
      await testUser.populate('roles.permissions');

      const hasReadPermission = await testUser.hasPermission('user', 'read');
      expect(hasReadPermission).toBe(true);

      const hasDeletePermission = await testUser.hasPermission('user', 'delete');
      expect(hasDeletePermission).toBe(false);
    });

    it('should generate full name', () => {
      expect(testUser.fullName).toBe('Test User');
    });

    it('should exclude password from JSON', () => {
      const userJSON = testUser.toJSON();
      expect(userJSON.password).toBeUndefined();
    });
  });

  describe('User Validation', () => {
    it('should require email', async () => {
      const userData = {
        password: 'TestPassword123!',
        firstName: 'Test',
        lastName: 'User'
      };

      await expect(User.create(userData)).rejects.toThrow();
    });

    it('should require firstName', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'TestPassword123!',
        lastName: 'User'
      };

      await expect(User.create(userData)).rejects.toThrow();
    });

    it('should require lastName', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'TestPassword123!',
        firstName: 'Test'
      };

      await expect(User.create(userData)).rejects.toThrow();
    });

    it('should set default values', async () => {
      const user = await User.create({
        email: 'test@example.com',
        password: 'TestPassword123!',
        firstName: 'Test',
        lastName: 'User'
      });

      expect(user.isActive).toBe(true);
      expect(user.isEmailVerified).toBe(false);
      expect(user.roles).toHaveLength(0);
      expect(user.refreshTokens).toHaveLength(0);
    });
  });
});