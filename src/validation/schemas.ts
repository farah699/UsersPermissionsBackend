import Joi from 'joi';

// User validation schemas
export const createUserSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Please provide a valid email address',
      'any.required': 'Email is required'
    }),
  password: Joi.string()
    .min(8)
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]'))
    .required()
    .messages({
      'string.min': 'Password must be at least 8 characters long',
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      'any.required': 'Password is required'
    }),
  firstName: Joi.string()
    .trim()
    .min(2)
    .max(50)
    .required()
    .messages({
      'string.min': 'First name must be at least 2 characters long',
      'string.max': 'First name cannot exceed 50 characters',
      'any.required': 'First name is required'
    }),
  lastName: Joi.string()
    .trim()
    .min(2)
    .max(50)
    .required()
    .messages({
      'string.min': 'Last name must be at least 2 characters long',
      'string.max': 'Last name cannot exceed 50 characters',
      'any.required': 'Last name is required'
    }),
  roles: Joi.array()
    .items(Joi.string().hex().length(24))
    .optional()
    .messages({
      'array.base': 'Roles must be an array',
      'string.hex': 'Each role must be a valid ObjectId',
      'string.length': 'Each role must be a valid ObjectId'
    })
});

export const updateUserSchema = Joi.object({
  email: Joi.string()
    .email()
    .optional()
    .messages({
      'string.email': 'Please provide a valid email address'
    }),
  firstName: Joi.string()
    .trim()
    .min(2)
    .max(50)
    .optional()
    .messages({
      'string.min': 'First name must be at least 2 characters long',
      'string.max': 'First name cannot exceed 50 characters'
    }),
  lastName: Joi.string()
    .trim()
    .min(2)
    .max(50)
    .optional()
    .messages({
      'string.min': 'Last name must be at least 2 characters long',
      'string.max': 'Last name cannot exceed 50 characters'
    }),
  roles: Joi.array()
    .items(Joi.string().hex().length(24))
    .optional()
    .messages({
      'array.base': 'Roles must be an array',
      'string.hex': 'Each role must be a valid ObjectId',
      'string.length': 'Each role must be a valid ObjectId'
    }),
  isActive: Joi.boolean().optional()
});

export const changePasswordSchema = Joi.object({
  currentPassword: Joi.string()
    .required()
    .messages({
      'any.required': 'Current password is required'
    }),
  newPassword: Joi.string()
    .min(8)
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]'))
    .required()
    .messages({
      'string.min': 'New password must be at least 8 characters long',
      'string.pattern.base': 'New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      'any.required': 'New password is required'
    }),
  confirmPassword: Joi.string()
    .required()
    .messages({
      'any.required': 'Password confirmation is required'
    })
});

// Auth validation schemas
export const loginSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Please provide a valid email address',
      'any.required': 'Email is required'
    }),
  password: Joi.string()
    .required()
    .messages({
      'any.required': 'Password is required'
    })
});

export const refreshTokenSchema = Joi.object({
  refreshToken: Joi.string()
    .required()
    .messages({
      'any.required': 'Refresh token is required'
    })
});

export const forgotPasswordSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Please provide a valid email address',
      'any.required': 'Email is required'
    })
});

export const resetPasswordSchema = Joi.object({
  token: Joi.string()
    .required()
    .messages({
      'any.required': 'Reset token is required'
    }),
  password: Joi.string()
    .min(8)
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]'))
    .required()
    .messages({
      'string.min': 'Password must be at least 8 characters long',
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      'any.required': 'Password is required'
    })
});

// Role validation schemas
export const createRoleSchema = Joi.object({
  name: Joi.string()
    .trim()
    .min(2)
    .max(50)
    .required()
    .messages({
      'string.min': 'Role name must be at least 2 characters long',
      'string.max': 'Role name cannot exceed 50 characters',
      'any.required': 'Role name is required'
    }),
  description: Joi.string()
    .trim()
    .max(500)
    .optional()
    .messages({
      'string.max': 'Description cannot exceed 500 characters'
    }),
  permissions: Joi.array()
    .items(Joi.string().hex().length(24))
    .optional()
    .messages({
      'array.base': 'Permissions must be an array',
      'string.hex': 'Each permission must be a valid ObjectId',
      'string.length': 'Each permission must be a valid ObjectId'
    })
});

export const updateRoleSchema = Joi.object({
  name: Joi.string()
    .trim()
    .min(2)
    .max(50)
    .optional()
    .messages({
      'string.min': 'Role name must be at least 2 characters long',
      'string.max': 'Role name cannot exceed 50 characters'
    }),
  description: Joi.string()
    .trim()
    .max(500)
    .optional()
    .allow('')
    .messages({
      'string.max': 'Description cannot exceed 500 characters'
    }),
  permissions: Joi.array()
    .items(Joi.string().hex().length(24))
    .optional()
    .messages({
      'array.base': 'Permissions must be an array',
      'string.hex': 'Each permission must be a valid ObjectId',
      'string.length': 'Each permission must be a valid ObjectId'
    }),
  isActive: Joi.boolean().optional()
});

// Permission validation schemas
export const createPermissionSchema = Joi.object({
  name: Joi.string()
    .trim()
    .min(2)
    .max(100)
    .required()
    .messages({
      'string.min': 'Permission name must be at least 2 characters long',
      'string.max': 'Permission name cannot exceed 100 characters',
      'any.required': 'Permission name is required'
    }),
  resource: Joi.string()
    .trim()
    .lowercase()
    .min(2)
    .max(50)
    .required()
    .messages({
      'string.min': 'Resource name must be at least 2 characters long',
      'string.max': 'Resource name cannot exceed 50 characters',
      'any.required': 'Resource is required'
    }),
  action: Joi.string()
    .valid('create', 'read', 'update', 'delete', 'manage')
    .required()
    .messages({
      'any.only': 'Action must be one of: create, read, update, delete, manage',
      'any.required': 'Action is required'
    }),
  description: Joi.string()
    .trim()
    .max(500)
    .optional()
    .messages({
      'string.max': 'Description cannot exceed 500 characters'
    })
});

// Query validation schemas
export const paginationSchema = Joi.object({
  page: Joi.number()
    .integer()
    .min(1)
    .default(1)
    .messages({
      'number.base': 'Page must be a number',
      'number.integer': 'Page must be an integer',
      'number.min': 'Page must be at least 1'
    }),
  limit: Joi.number()
    .integer()
    .min(1)
    .max(100)
    .default(10)
    .messages({
      'number.base': 'Limit must be a number',
      'number.integer': 'Limit must be an integer',
      'number.min': 'Limit must be at least 1',
      'number.max': 'Limit cannot exceed 100'
    }),
  search: Joi.string()
    .trim()
    .allow('')
    .optional()
    .messages({
      'string.base': 'Search must be a string'
    }),
  sortBy: Joi.string()
    .optional()
    .messages({
      'string.base': 'Sort field must be a string'
    }),
  sortOrder: Joi.string()
    .valid('asc', 'desc')
    .default('asc')
    .messages({
      'any.only': 'Sort order must be either "asc" or "desc"'
    }),
  isActive: Joi.boolean()
    .optional()
    .messages({
      'boolean.base': 'isActive must be a boolean'
    })
}).unknown(true);

// ObjectId validation
export const objectIdSchema = Joi.string()
  .hex()
  .length(24)
  .required()
  .messages({
    'string.hex': 'Must be a valid ObjectId',
    'string.length': 'Must be a valid ObjectId',
    'any.required': 'ID is required'
  });