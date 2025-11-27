import { Role } from '../../models/Role';
import { Permission } from '../../models/Permission';

describe('Role Model Tests', () => {
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
      },
      {
        name: 'role:manage',
        resource: 'role',
        action: 'manage',
        description: 'Manage roles'
      }
    ]);
  });

  describe('Role Creation', () => {
    it('should create a valid role', async () => {
      const roleData = {
        name: 'Admin',
        description: 'Administrator role',
        permissions: testPermissions.map(p => p._id),
        isActive: true
      };

      const role = await Role.create(roleData);

      expect(role.name).toBe(roleData.name);
      expect(role.description).toBe(roleData.description);
      expect(role.isActive).toBe(true);
      expect(role.permissions).toHaveLength(3);
      expect(role.createdAt).toBeDefined();
      expect(role.updatedAt).toBeDefined();
    });

    it('should require unique name', async () => {
      const roleData = {
        name: 'Duplicate Role',
        description: 'First role',
        permissions: [testPermissions[0]._id]
      };

      await Role.create(roleData);

      await expect(Role.create({
        ...roleData,
        description: 'Second role with same name'
      })).rejects.toThrow();
    });

    it('should set default values', async () => {
      const role = await Role.create({
        name: 'Basic Role',
        permissions: [testPermissions[0]._id]
      });

      expect(role.isActive).toBe(true);
      expect(role.description).toBeUndefined();
    });
  });

  describe('Role Validation', () => {
    it('should require name', async () => {
      const roleData = {
        description: 'Role without name',
        permissions: [testPermissions[0]._id]
      };

      await expect(Role.create(roleData)).rejects.toThrow();
    });

    it('should accept short names', async () => {
      const roleData = {
        name: 'ab',
        permissions: [testPermissions[0]._id]
      };

      const role = await Role.create(roleData);
      expect(role.name).toBe('ab');
    });

    it('should allow empty permissions array', async () => {
      const role = await Role.create({
        name: 'Empty Role',
        permissions: []
      });

      expect(role.permissions).toHaveLength(0);
    });
  });

  describe('Role Methods', () => {
    let testRole: any;

    beforeEach(async () => {
      testRole = await Role.create({
        name: 'Test Role',
        description: 'Role for testing',
        permissions: testPermissions.map(p => p._id)
      });
    });

    it('should check if role has specific permission', async () => {
      await testRole.populate('permissions');

      const hasUserRead = testRole.hasPermission('user', 'read');
      expect(hasUserRead).toBe(true);

      const hasUserDelete = testRole.hasPermission('user', 'delete');
      expect(hasUserDelete).toBe(false);
    });

    it('should add permission to role', async () => {
      const newPermission = await Permission.create({
        name: 'Update Users Test',
        resource: 'user',
        action: 'update',
        description: 'Update user information'
      });

      testRole.permissions.push(newPermission._id);
      await testRole.save();

      expect(testRole.permissions).toHaveLength(4);
      expect(testRole.permissions.map((p: any) => p.toString())).toContain(newPermission._id.toString());
    });

    it('should remove permission from role', async () => {
      const initialCount = testRole.permissions.length;
      const permissionToRemove = testPermissions[0]._id;

      testRole.permissions = testRole.permissions.filter(
        (p: any) => !p.equals(permissionToRemove)
      );
      await testRole.save();

      expect(testRole.permissions).toHaveLength(initialCount - 1);
      expect(testRole.permissions.map((p: any) => p.toString())).not.toContain(permissionToRemove.toString());
    });

    it('should not add duplicate permissions', async () => {
      const existingPermission = testPermissions[0]._id;
      const initialCount = testRole.permissions.length;

      // Try to add existing permission
      if (!testRole.permissions.some((p: any) => p.equals(existingPermission))) {
        testRole.permissions.push(existingPermission);
      }
      await testRole.save();

      expect(testRole.permissions).toHaveLength(initialCount);
    });
  });

  describe('Role Queries', () => {
    beforeEach(async () => {
      await Role.insertMany([
        {
          name: 'Active Role 1',
          permissions: [testPermissions[0]._id],
          isActive: true
        },
        {
          name: 'Active Role 2',
          permissions: [testPermissions[1]._id],
          isActive: true
        },
        {
          name: 'Inactive Role',
          permissions: [testPermissions[2]._id],
          isActive: false
        }
      ]);
    });

    it('should find active roles only', async () => {
      const activeRoles = await Role.find({ isActive: true });
      expect(activeRoles).toHaveLength(2);
    });

    it('should populate permissions correctly', async () => {
      const rolesWithPermissions = await Role.find().populate('permissions');
      
      rolesWithPermissions.forEach(role => {
        if (role.permissions.length > 0) {
          expect(role.permissions[0]).toHaveProperty('name');
          expect(role.permissions[0]).toHaveProperty('resource');
          expect(role.permissions[0]).toHaveProperty('action');
        }
      });
    });
  });
});