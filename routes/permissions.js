// File: routes/permissions.js
// Permission, Role, and Policy management routes

const express = require('express');
const { body, validationResult } = require('express-validator');
const { Permission, Role, Policy } = require('../models/Permission');
const User = require('../models/User');
const { requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// ===============================
// PERMISSIONS ROUTES
// ===============================

// Get all permissions
router.get('/permissions', requireRole(['admin', 'super_admin']), asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const skip = (page - 1) * limit;

  const filter = {};
  if (req.query.resource) {
    filter.resource = req.query.resource;
  }
  if (req.query.action) {
    filter.action = req.query.action;
  }
  if (req.query.isActive !== undefined) {
    filter.isActive = req.query.isActive === 'true';
  }

  const total = await Permission.countDocuments(filter);
  const permissions = await Permission.find(filter)
    .populate('createdBy', 'username fullName')
    .populate('updatedBy', 'username fullName')
    .sort({ resource: 1, action: 1 })
    .skip(skip)
    .limit(limit);

  res.json({
    success: true,
    data: permissions,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }
  });
}));

// Create permission
router.post('/permissions', requireRole(['admin', 'super_admin']), [
  body('name')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Name is required and must be less than 100 characters'),
  body('displayName')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Display name is required'),
  body('resource')
    .trim()
    .notEmpty()
    .withMessage('Resource is required'),
  body('action')
    .isIn(['create', 'read', 'update', 'delete', 'execute', 'manage'])
    .withMessage('Invalid action')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  // Check if permission already exists
  const existingPermission = await Permission.findOne({
    name: req.body.name
  });

  if (existingPermission) {
    return res.status(400).json({
      success: false,
      error: 'Permission with this name already exists'
    });
  }

  const permission = new Permission({
    ...req.body,
    createdBy: req.user._id
  });

  await permission.save();

  res.status(201).json({
    success: true,
    message: 'Permission created successfully',
    data: permission
  });
}));

// Update permission
router.put('/permissions/:id', requireRole(['admin', 'super_admin']), [
  body('displayName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Display name must be between 1 and 100 characters'),
  body('description')
    .optional()
    .trim(),
  body('isActive')
    .optional()
    .isBoolean()
    .withMessage('isActive must be a boolean')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  const permission = await Permission.findById(req.params.id);
  if (!permission) {
    return res.status(404).json({
      success: false,
      error: 'Permission not found'
    });
  }

  const allowedUpdates = ['displayName', 'description', 'conditions', 'attributes', 'priority', 'isActive'];
  Object.keys(req.body).forEach(key => {
    if (allowedUpdates.includes(key)) {
      permission[key] = req.body[key];
    }
  });

  permission.updatedBy = req.user._id;
  await permission.save();

  res.json({
    success: true,
    message: 'Permission updated successfully',
    data: permission
  });
}));

// Delete permission
router.delete('/permissions/:id', requireRole(['super_admin']), asyncHandler(async (req, res) => {
  const permission = await Permission.findById(req.params.id);
  if (!permission) {
    return res.status(404).json({
      success: false,
      error: 'Permission not found'
    });
  }

  // Check if permission is used in any roles
  const rolesUsingPermission = await Role.countDocuments({
    permissions: permission._id
  });

  if (rolesUsingPermission > 0) {
    return res.status(400).json({
      success: false,
      error: 'Cannot delete permission that is assigned to roles'
    });
  }

  await permission.deleteOne();

  res.json({
    success: true,
    message: 'Permission deleted successfully'
  });
}));

// ===============================
// ROLES ROUTES
// ===============================

// Get all roles
router.get('/roles', requireRole(['admin', 'super_admin']), asyncHandler(async (req, res) => {
  const roles = await Role.find({ isActive: true })
    .populate('permissions')
    .populate('inheritFrom', 'name displayName')
    .populate('createdBy', 'username fullName')
    .sort({ level: 1, name: 1 });

  res.json({
    success: true,
    data: roles
  });
}));

// Create role
router.post('/roles', requireRole(['admin', 'super_admin']), [
  body('name')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Name is required and must be less than 50 characters')
    .matches(/^[a-z_]+$/)
    .withMessage('Name can only contain lowercase letters and underscores'),
  body('displayName')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Display name is required'),
  body('permissions')
    .optional()
    .isArray()
    .withMessage('Permissions must be an array')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  // Check if role already exists
  const existingRole = await Role.findOne({ name: req.body.name });
  if (existingRole) {
    return res.status(400).json({
      success: false,
      error: 'Role with this name already exists'
    });
  }

  // Validate permissions exist
  if (req.body.permissions && req.body.permissions.length > 0) {
    const permissionCount = await Permission.countDocuments({
      _id: { $in: req.body.permissions },
      isActive: true
    });

    if (permissionCount !== req.body.permissions.length) {
      return res.status(400).json({
        success: false,
        error: 'Some permissions are invalid or inactive'
      });
    }
  }

  const role = new Role({
    ...req.body,
    createdBy: req.user._id
  });

  await role.save();
  await role.populate('permissions');

  res.status(201).json({
    success: true,
    message: 'Role created successfully',
    data: role
  });
}));

// Update role
router.put('/roles/:id', requireRole(['admin', 'super_admin']), [
  body('displayName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Display name must be between 1 and 100 characters'),
  body('permissions')
    .optional()
    .isArray()
    .withMessage('Permissions must be an array')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  const role = await Role.findById(req.params.id);
  if (!role) {
    return res.status(404).json({
      success: false,
      error: 'Role not found'
    });
  }

  // Don't allow modification of system roles except by super_admin
  if (role.isSystemRole && req.user.role !== 'super_admin') {
    return res.status(403).json({
      success: false,
      error: 'Only super admin can modify system roles'
    });
  }

  // Validate permissions if provided
  if (req.body.permissions && req.body.permissions.length > 0) {
    const permissionCount = await Permission.countDocuments({
      _id: { $in: req.body.permissions },
      isActive: true
    });

    if (permissionCount !== req.body.permissions.length) {
      return res.status(400).json({
        success: false,
        error: 'Some permissions are invalid or inactive'
      });
    }
  }

  const allowedUpdates = ['displayName', 'description', 'permissions', 'inheritFrom', 'level', 'isActive'];
  Object.keys(req.body).forEach(key => {
    if (allowedUpdates.includes(key)) {
      role[key] = req.body[key];
    }
  });

  role.updatedBy = req.user._id;
  await role.save();
  await role.populate('permissions');

  res.json({
    success: true,
    message: 'Role updated successfully',
    data: role
  });
}));

// Delete role
router.delete('/roles/:id', requireRole(['super_admin']), asyncHandler(async (req, res) => {
  const role = await Role.findById(req.params.id);
  if (!role) {
    return res.status(404).json({
      success: false,
      error: 'Role not found'
    });
  }

  // Don't allow deletion of system roles
  if (role.isSystemRole) {
    return res.status(400).json({
      success: false,
      error: 'Cannot delete system role'
    });
  }

  // Check if role is assigned to any users
  const usersWithRole = await User.countDocuments({ role: role.name });
  if (usersWithRole > 0) {
    return res.status(400).json({
      success: false,
      error: 'Cannot delete role that is assigned to users'
    });
  }

  await role.deleteOne();

  res.json({
    success: true,
    message: 'Role deleted successfully'
  });
}));

// Assign role to user
router.post('/roles/:roleId/assign', requireRole(['admin', 'super_admin']), [
  body('userId')
    .notEmpty()
    .withMessage('User ID is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  const role = await Role.findById(req.params.roleId);
  if (!role) {
    return res.status(404).json({
      success: false,
      error: 'Role not found'
    });
  }

  const user = await User.findById(req.body.userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  // Only super_admin can assign super_admin role
  if (role.name === 'super_admin' && req.user.role !== 'super_admin') {
    return res.status(403).json({
      success: false,
      error: 'Only super admin can assign super admin role'
    });
  }

  user.role = role.name;
  await user.save();

  res.json({
    success: true,
    message: 'Role assigned successfully',
    data: {
      userId: user._id,
      role: role.name
    }
  });
}));

// ===============================
// POLICIES ROUTES
// ===============================

// Get all policies
router.get('/policies', requireRole(['admin', 'super_admin']), asyncHandler(async (req, res) => {
  const policies = await Policy.find({ isActive: true })
    .populate('createdBy', 'username fullName')
    .sort({ priority: -1, name: 1 });

  res.json({
    success: true,
    data: policies
  });
}));

// Create policy
router.post('/policies', requireRole(['admin', 'super_admin']), [
  body('name')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Name is required and must be less than 100 characters'),
  body('displayName')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Display name is required'),
  body('type')
    .isIn(['rbac', 'abac', 'hybrid'])
    .withMessage('Invalid policy type'),
  body('rules')
    .isArray({ min: 1 })
    .withMessage('At least one rule is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  // Check if policy already exists
  const existingPolicy = await Policy.findOne({ name: req.body.name });
  if (existingPolicy) {
    return res.status(400).json({
      success: false,
      error: 'Policy with this name already exists'
    });
  }

  const policy = new Policy({
    ...req.body,
    createdBy: req.user._id
  });

  await policy.save();

  res.status(201).json({
    success: true,
    message: 'Policy created successfully',
    data: policy
  });
}));

// Update policy
router.put('/policies/:id', requireRole(['admin', 'super_admin']), [
  body('displayName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Display name must be between 1 and 100 characters'),
  body('rules')
    .optional()
    .isArray({ min: 1 })
    .withMessage('At least one rule is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  const policy = await Policy.findById(req.params.id);
  if (!policy) {
    return res.status(404).json({
      success: false,
      error: 'Policy not found'
    });
  }

  const allowedUpdates = ['displayName', 'description', 'rules', 'priority', 'isActive'];
  Object.keys(req.body).forEach(key => {
    if (allowedUpdates.includes(key)) {
      policy[key] = req.body[key];
    }
  });

  policy.updatedBy = req.user._id;
  await policy.save();

  res.json({
    success: true,
    message: 'Policy updated successfully',
    data: policy
  });
}));

// Delete policy
router.delete('/policies/:id', requireRole(['super_admin']), asyncHandler(async (req, res) => {
  const policy = await Policy.findById(req.params.id);
  if (!policy) {
    return res.status(404).json({
      success: false,
      error: 'Policy not found'
    });
  }

  await policy.deleteOne();

  res.json({
    success: true,
    message: 'Policy deleted successfully'
  });
}));

// Test policy evaluation
router.post('/policies/:id/test', requireRole(['admin', 'super_admin']), [
  body('subject')
    .notEmpty()
    .withMessage('Subject is required'),
  body('resource')
    .notEmpty()
    .withMessage('Resource is required'),
  body('action')
    .notEmpty()
    .withMessage('Action is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  const policy = await Policy.findById(req.params.id);
  if (!policy) {
    return res.status(404).json({
      success: false,
      error: 'Policy not found'
    });
  }

  const { subject, resource, action, context = {} } = req.body;
  const result = policy.evaluate(subject, resource, action, context);

  res.json({
    success: true,
    data: {
      result: result.effect,
      reason: result.reason,
      rule: result.rule
    }
  });
}));

// Get permission summary
router.get('/summary', requireRole(['admin', 'super_admin']), asyncHandler(async (req, res) => {
  const [permissionCount, roleCount, policyCount, usersByRole] = await Promise.all([
    Permission.countDocuments({ isActive: true }),
    Role.countDocuments({ isActive: true }),
    Policy.countDocuments({ isActive: true }),
    User.aggregate([
      {
        $group: {
          _id: '$role',
          count: { $sum: 1 }
        }
      }
    ])
  ]);

  res.json({
    success: true,
    data: {
      permissions: permissionCount,
      roles: roleCount,
      policies: policyCount,
      usersByRole
    }
  });
}));

module.exports = router;