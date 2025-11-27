import { Permission } from '../../models/Permission';

describe('Permission Model Tests', () => {
  describe('Permission Creation', () => {
    it('should create a valid permission', async () => {
      const permissionData = {
        name: 'user:read',
        resource: 'user',
        action: 'read',
        description: 'Read user information'
      };

      const permission = await Permission.create(permissionData);

      expect(permission.name).toBe(permissionData.name);
      expect(permission.resource).toBe(permissionData.resource);
      expect(permission.action).toBe(permissionData.action);
      expect(permission.description).toBe(permissionData.description);
      expect(permission.createdAt).toBeDefined();
      expect(permission.updatedAt).toBeDefined();
    });

    it('should require unique name', async () => {
      const permissionData = {
        name: 'duplicate:permission',
        resource: 'test',
        action: 'read'
      };

      await Permission.create(permissionData);

      await expect(Permission.create(permissionData)).rejects.toThrow();
    });

    it('should create permission without description', async () => {
      const permission = await Permission.create({
        name: 'test:read',
        resource: 'test',
        action: 'read'
      });

      expect(permission.description).toBeUndefined();
    });
  });

  describe('Permission Validation', () => {
    it('should require name', async () => {
      const permissionData = {
        resource: 'user',
        action: 'read'
      };

      await expect(Permission.create(permissionData)).rejects.toThrow();
    });

    it('should require resource', async () => {
      const permissionData = {
        name: 'test:permission',
        action: 'read'
      };

      await expect(Permission.create(permissionData)).rejects.toThrow();
    });

    it('should require action', async () => {
      const permissionData = {
        name: 'test:permission',
        resource: 'user'
      };

      await expect(Permission.create(permissionData)).rejects.toThrow();
    });

    it('should validate action enum values', async () => {
      const permissionData = {
        name: 'test:invalid',
        resource: 'user',
        action: 'invalid_action'
      };

      await expect(Permission.create(permissionData)).rejects.toThrow();
    });

    it('should accept valid action enum values', async () => {
      const validActions = ['create', 'read', 'update', 'delete', 'manage'];

      for (const action of validActions) {
        const permission = await Permission.create({
          name: `test:${action}`,
          resource: 'test',
          action: action
        });

        expect(permission.action).toBe(action);
      }
    });
  });

  describe('Permission Static Methods', () => {
    it('should generate common permissions', () => {
      const commonPermissions = (Permission as any).getCommonPermissions();

      expect(Array.isArray(commonPermissions)).toBe(true);
      expect(commonPermissions.length).toBeGreaterThan(0);

      // Check structure of generated permissions
      commonPermissions.forEach((permission: any) => {
        expect(permission).toHaveProperty('name');
        expect(permission).toHaveProperty('resource');
        expect(permission).toHaveProperty('action');
        expect(permission).toHaveProperty('description');
      });

      // Check for expected permissions
      const permissionNames = commonPermissions.map((p: any) => p.name);
      expect(permissionNames).toContain('Create Users');
      expect(permissionNames).toContain('Read Users');
      expect(permissionNames).toContain('Update Users');
      expect(permissionNames).toContain('Delete Users');
      expect(permissionNames).toContain('Manage Roles');
      expect(permissionNames).toContain('Read Permissions');
      expect(permissionNames).toContain('Read Audit Logs');
    });

    it('should generate permissions for all resources', () => {
      const commonPermissions = (Permission as any).getCommonPermissions();
      const resources = [...new Set(commonPermissions.map((p: any) => p.resource))];

      expect(resources).toContain('user');
      expect(resources).toContain('role');
      expect(resources).toContain('permission');
      expect(resources).toContain('audit');
    });

    it('should generate permissions for all actions', () => {
      const commonPermissions = (Permission as any).getCommonPermissions();
      const actions = [...new Set(commonPermissions.map((p: any) => p.action))];

      expect(actions).toContain('create');
      expect(actions).toContain('read');
      expect(actions).toContain('update');
      expect(actions).toContain('delete');
      expect(actions).toContain('manage');
    });
  });

  describe('Permission Queries', () => {
    beforeEach(async () => {
      // Seed some test permissions
      await Permission.insertMany([
        {
          name: 'user:create',
          resource: 'user',
          action: 'create',
          description: 'Create users'
        },
        {
          name: 'user:read',
          resource: 'user',
          action: 'read',
          description: 'Read users'
        },
        {
          name: 'role:manage',
          resource: 'role',
          action: 'manage',
          description: 'Manage roles'
        }
      ]);
    });

    it('should find permissions by resource', async () => {
      const userPermissions = await Permission.find({ resource: 'user' });
      expect(userPermissions).toHaveLength(2);
      userPermissions.forEach(permission => {
        expect(permission.resource).toBe('user');
      });
    });

    it('should find permissions by action', async () => {
      const createPermissions = await Permission.find({ action: 'create' });
      expect(createPermissions).toHaveLength(1);
      expect(createPermissions[0].action).toBe('create');
    });

    it('should find permission by resource and action', async () => {
      const permission = await Permission.findOne({
        resource: 'user',
        action: 'read'
      });

      expect(permission).toBeTruthy();
      expect(permission?.name).toBe('user:read');
    });
  });

  describe('Permission Instance Methods', () => {
    let testPermission: any;

    beforeEach(async () => {
      testPermission = await Permission.create({
        name: 'Test Permission',
        resource: 'test',
        action: 'read',
        description: 'Test permission'
      });
    });

    it('should have correct properties', () => {
      expect(testPermission.name).toBe('Test Permission');
      expect(testPermission.resource).toBe('test');
      expect(testPermission.action).toBe('read');
    });

    it('should match resource and action directly', () => {
      expect(testPermission.resource).toBe('test');
      expect(testPermission.action).toBe('read');
    });
  });
});