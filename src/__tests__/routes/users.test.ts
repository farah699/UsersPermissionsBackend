import request from 'supertest';
import { Express } from 'express';
import { User } from '../../models/User';
import { Role } from '../../models/Role';
import { Permission } from '../../models/Permission';
import { createTestApp } from '../helpers/testApp';

describe('Users Routes Integration Tests', () => {
  let app: Express;
  let adminUser: any;
  let regularUser: any;
  let adminRole: any;
  let userRole: any;
  let adminToken: string;
  let userToken: string;

  beforeAll(async () => {
    app = createTestApp();
  });

  beforeEach(async () => {
    // Create permissions
    const permissions = await Permission.insertMany([
      { name: 'user:create', resource: 'user', action: 'create' },
      { name: 'user:read', resource: 'user', action: 'read' },
      { name: 'user:update', resource: 'user', action: 'update' },
      { name: 'user:delete', resource: 'user', action: 'delete' },
      { name: 'user:manage', resource: 'user', action: 'manage' }
    ]);

    // Create roles
    adminRole = await Role.create({
      name: 'Admin',
      permissions: permissions.map(p => p._id),
      isActive: true
    });

    userRole = await Role.create({
      name: 'User',
      permissions: [permissions.find(p => p.name === 'user:read')?._id],
      isActive: true
    });

    // Create users
    adminUser = await User.create({
      email: 'admin@test.com',
      password: 'AdminPass123!',
      firstName: 'Admin',
      lastName: 'User',
      roles: [adminRole._id],
      isActive: true,
      isEmailVerified: true
    });

    regularUser = await User.create({
      email: 'user@test.com',
      password: 'UserPass123!',
      firstName: 'Regular',
      lastName: 'User',
      roles: [userRole._id],
      isActive: true,
      isEmailVerified: true
    });

    // Get tokens
    const adminLogin = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'admin@test.com',
        password: 'AdminPass123!'
      });
    adminToken = adminLogin.body.data.accessToken;

    const userLogin = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'user@test.com',
        password: 'UserPass123!'
      });
    userToken = userLogin.body.data.accessToken;
  });

  describe('GET /api/users', () => {
    it('should get all users with admin permissions', async () => {
      const response = await request(app)
        .get('/api/users')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.users).toHaveLength(2);
      expect(response.body.data.pagination).toBeDefined();
    });

    it('should get users with regular user permissions', async () => {
      const response = await request(app)
        .get('/api/users')
        .set('Authorization', `Bearer ${userToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .get('/api/users');

      expect(response.status).toBe(401);
    });

    it('should support pagination', async () => {
      const response = await request(app)
        .get('/api/users')
        .query({ page: 1, limit: 1 })
        .set('Authorization', `Bearer ${adminToken}`);

      expect(response.status).toBe(200);
      expect(response.body.data.users).toHaveLength(1);
      expect(response.body.data.pagination.page).toBe(1);
      expect(response.body.data.pagination.limit).toBe(1);
    });

    it('should support search', async () => {
      const response = await request(app)
        .get('/api/users')
        .query({ search: 'admin' })
        .set('Authorization', `Bearer ${adminToken}`);

      expect(response.status).toBe(200);
      expect(response.body.data.users).toHaveLength(1);
      expect(response.body.data.users[0].email).toContain('admin');
    });
  });

  describe('POST /api/users', () => {
    const newUserData = {
      email: 'newuser@test.com',
      password: 'NewUserPass123!',
      firstName: 'New',
      lastName: 'User',
      roles: []
    };

    it('should create user with admin permissions', async () => {
      const response = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ ...newUserData, roles: [userRole._id] });

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.data.user.email).toBe(newUserData.email);
      expect(response.body.data.user.password).toBeUndefined();
    });

    it('should not create user without admin permissions', async () => {
      const response = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${userToken}`)
        .send(newUserData);

      expect(response.status).toBe(403);
    });

    it('should validate required fields', async () => {
      const response = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: 'invalid-email',
          firstName: 'Test'
          // Missing required fields
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });

    it('should not create user with duplicate email', async () => {
      const response = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          ...newUserData,
          email: 'admin@test.com' // Existing email
        });

      expect(response.status).toBe(400);
    });
  });

  describe('GET /api/users/:id', () => {
    it('should get user by id with admin permissions', async () => {
      const response = await request(app)
        .get(`/api/users/${regularUser._id}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.user._id).toBe(regularUser._id.toString());
    });

    it('should get user by id with regular permissions', async () => {
      const response = await request(app)
        .get(`/api/users/${regularUser._id}`)
        .set('Authorization', `Bearer ${userToken}`);

      expect(response.status).toBe(200);
    });

    it('should return 404 for non-existent user', async () => {
      const nonExistentId = '507f1f77bcf86cd799439011';
      const response = await request(app)
        .get(`/api/users/${nonExistentId}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(response.status).toBe(404);
    });

    it('should return 400 for invalid ObjectId', async () => {
      const response = await request(app)
        .get('/api/users/invalid-id')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(response.status).toBe(400);
    });
  });

  describe('PUT /api/users/:id', () => {
    const updateData = {
      firstName: 'Updated',
      lastName: 'Name'
    };

    it('should update user with admin permissions', async () => {
      const response = await request(app)
        .put(`/api/users/${regularUser._id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send(updateData);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.user.firstName).toBe(updateData.firstName);
    });

    it('should not update user without admin permissions', async () => {
      const response = await request(app)
        .put(`/api/users/${regularUser._id}`)
        .set('Authorization', `Bearer ${userToken}`)
        .send(updateData);

      expect(response.status).toBe(403);
    });

    it('should not update to duplicate email', async () => {
      const response = await request(app)
        .put(`/api/users/${regularUser._id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: 'admin@test.com' // Existing email
        });

      expect(response.status).toBe(400);
    });

    it('should update user roles', async () => {
      const response = await request(app)
        .put(`/api/users/${regularUser._id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          roles: [adminRole._id]
        });

      expect(response.status).toBe(200);
      expect(response.body.data.user.roles).toContain(adminRole._id.toString());
    });
  });

  describe('DELETE /api/users/:id', () => {
    it('should delete user with admin permissions', async () => {
      const response = await request(app)
        .delete(`/api/users/${regularUser._id}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);

      // Verify user is deleted
      const deletedUser = await User.findById(regularUser._id);
      expect(deletedUser).toBeNull();
    });

    it('should not delete user without admin permissions', async () => {
      const response = await request(app)
        .delete(`/api/users/${regularUser._id}`)
        .set('Authorization', `Bearer ${userToken}`);

      expect(response.status).toBe(403);
    });

    it('should return 404 for non-existent user', async () => {
      const nonExistentId = '507f1f77bcf86cd799439011';
      const response = await request(app)
        .delete(`/api/users/${nonExistentId}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(response.status).toBe(404);
    });

    it('should not delete self', async () => {
      const response = await request(app)
        .delete(`/api/users/${adminUser._id}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('Cannot delete your own account');
    });
  });

  describe('PATCH /api/users/:id/status', () => {
    it('should toggle user status with admin permissions', async () => {
      const response = await request(app)
        .patch(`/api/users/${regularUser._id}/status`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ isActive: false });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.user.isActive).toBe(false);
    });

    it('should not change status without admin permissions', async () => {
      const response = await request(app)
        .patch(`/api/users/${regularUser._id}/status`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ isActive: false });

      expect(response.status).toBe(403);
    });

    it('should not deactivate self', async () => {
      const response = await request(app)
        .patch(`/api/users/${adminUser._id}/status`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ isActive: false });

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('Cannot deactivate your own account');
    });
  });
});