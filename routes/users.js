// File: routes/users.js
// User management routes

const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const { requireRole, requirePermission } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// Get all users
router.get('/', requirePermission('User', 'read'), asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 10, 100);
  const skip = (page - 1) * limit;

  const filter = {};
  
  // Apply filters
  if (req.query.role) {
    filter.role = req.query.role;
  }
  
  if (req.query.department) {
    filter.department = req.query.department;
  }
  
  if (req.query.isActive !== undefined) {
    filter.isActive = req.query.isActive === 'true';
  }
  
  if (req.query.search) {
    filter.$or = [
      { username: { $regex: req.query.search, $options: 'i' } },
      { email: { $regex: req.query.search, $options: 'i' } },
      { firstName: { $regex: req.query.search, $options: 'i' } },
      { lastName: { $regex: req.query.search, $options: 'i' } }
    ];
  }

  const total = await User.countDocuments(filter);
  const users = await User.find(filter)
    .select('-password -refreshTokens')
    .populate('avatar')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);

  res.json({
    success: true,
    data: users,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }
  });
}));

// Get single user
router.get('/:id', requirePermission('User', 'read'), asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id)
    .select('-password -refreshTokens')
    .populate('avatar');

  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  res.json({
    success: true,
    data: user
  });
}));

// Create new user
router.post('/', requirePermission('User', 'create'), [
  body('username')
    .isLength({ min: 3, max: 50 })
    .withMessage('Username must be between 3 and 50 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  body('firstName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name is required and must be less than 50 characters'),
  body('lastName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name is required and must be less than 50 characters'),
  body('role')
    .optional()
    .isIn(['super_admin', 'admin', 'manager', 'user'])
    .withMessage('Invalid role')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  // Check if user already exists
  const existingUser = await User.findOne({
    $or: [
      { email: req.body.email.toLowerCase() },
      { username: req.body.username }
    ]
  });

  if (existingUser) {
    return res.status(400).json({
      success: false,
      error: 'User with this email or username already exists'
    });
  }

  // Only super_admin can create other super_admins
  if (req.body.role === 'super_admin' && req.user.role !== 'super_admin') {
    return res.status(403).json({
      success: false,
      error: 'Only super admin can create other super admins'
    });
  }

  const userData = {
    username: req.body.username,
    email: req.body.email.toLowerCase(),
    password: req.body.password,
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    role: req.body.role || 'user',
    department: req.body.department,
    phone: req.body.phone,
    address: req.body.address,
    attributes: req.body.attributes || {}
  };

  const user = new User(userData);
  await user.save();

  // Remove password from response
  const userResponse = user.toObject();
  delete userResponse.password;
  delete userResponse.refreshTokens;

  res.status(201).json({
    success: true,
    message: 'User created successfully',
    data: userResponse
  });
}));

// Update user
router.put('/:id', requirePermission('User', 'update'), [
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be between 1 and 50 characters'),
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be between 1 and 50 characters'),
  body('role')
    .optional()
    .isIn(['super_admin', 'admin', 'manager', 'user'])
    .withMessage('Invalid role'),
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

  const user = await User.findById(req.params.id);
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  // Prevent users from updating their own role or status
  if (user._id.toString() === req.user._id.toString()) {
    if (req.body.role || req.body.isActive !== undefined) {
      return res.status(400).json({
        success: false,
        error: 'Cannot modify your own role or status'
      });
    }
  }

  // Only super_admin can modify super_admin accounts
  if (user.role === 'super_admin' && req.user.role !== 'super_admin') {
    return res.status(403).json({
      success: false,
      error: 'Only super admin can modify super admin accounts'
    });
  }

  // Only super_admin can assign super_admin role
  if (req.body.role === 'super_admin' && req.user.role !== 'super_admin') {
    return res.status(403).json({
      success: false,
      error: 'Only super admin can assign super admin role'
    });
  }

  // Check if email is being updated and if it's unique
  if (req.body.email && req.body.email !== user.email) {
    const existingUser = await User.findOne({
      email: req.body.email,
      _id: { $ne: user._id }
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'Email already in use'
      });
    }
  }

  // Update allowed fields
  const allowedUpdates = [
    'email', 'firstName', 'lastName', 'role', 'department', 
    'phone', 'address', 'isActive', 'permissions', 'attributes'
  ];
  
  Object.keys(req.body).forEach(key => {
    if (allowedUpdates.includes(key)) {
      user[key] = req.body[key];
    }
  });

  await user.save();

  // Remove sensitive data from response
  const userResponse = user.toObject();
  delete userResponse.password;
  delete userResponse.refreshTokens;

  res.json({
    success: true,
    message: 'User updated successfully',
    data: userResponse
  });
}));

// Delete user
router.delete('/:id', requirePermission('User', 'delete'), asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);
  
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  // Prevent users from deleting themselves
  if (user._id.toString() === req.user._id.toString()) {
    return res.status(400).json({
      success: false,
      error: 'Cannot delete your own account'
    });
  }

  // Only super_admin can delete other super_admins
  if (user.role === 'super_admin' && req.user.role !== 'super_admin') {
    return res.status(403).json({
      success: false,
      error: 'Only super admin can delete super admin accounts'
    });
  }

  await user.deleteOne();

  res.json({
    success: true,
    message: 'User deleted successfully'
  });
}));

// Activate/Deactivate user
router.patch('/:id/status', requirePermission('User', 'update'), [
  body('isActive')
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

  const user = await User.findById(req.params.id);
  
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  // Prevent users from deactivating themselves
  if (user._id.toString() === req.user._id.toString()) {
    return res.status(400).json({
      success: false,
      error: 'Cannot modify your own status'
    });
  }

  // Only super_admin can modify super_admin status
  if (user.role === 'super_admin' && req.user.role !== 'super_admin') {
    return res.status(403).json({
      success: false,
      error: 'Only super admin can modify super admin status'
    });
  }

  user.isActive = req.body.isActive;
  
  // If deactivating, remove all refresh tokens
  if (!req.body.isActive) {
    user.refreshTokens = [];
  }
  
  await user.save();

  res.json({
    success: true,
    message: `User ${req.body.isActive ? 'activated' : 'deactivated'} successfully`,
    data: {
      id: user._id,
      isActive: user.isActive
    }
  });
}));

// Reset user password
router.post('/:id/reset-password', requirePermission('User', 'update'), [
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('New password must contain at least one uppercase letter, one lowercase letter, and one number')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  const user = await User.findById(req.params.id);
  
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  // Only super_admin can reset super_admin passwords
  if (user.role === 'super_admin' && req.user.role !== 'super_admin') {
    return res.status(403).json({
      success: false,
      error: 'Only super admin can reset super admin passwords'
    });
  }

  user.password = req.body.newPassword;
  user.refreshTokens = []; // Force re-login
  await user.save();

  res.json({
    success: true,
    message: 'Password reset successfully'
  });
}));

// Get user permissions
router.get('/:id/permissions', requirePermission('User', 'read'), asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id).select('permissions role');
  
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  res.json({
    success: true,
    data: {
      role: user.role,
      permissions: user.permissions
    }
  });
}));

// Update user permissions
router.put('/:id/permissions', requireRole(['super_admin', 'admin']), [
  body('permissions')
    .isArray()
    .withMessage('Permissions must be an array'),
  body('permissions.*.resource')
    .notEmpty()
    .withMessage('Permission resource is required'),
  body('permissions.*.actions')
    .isArray()
    .withMessage('Permission actions must be an array')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  const user = await User.findById(req.params.id);
  
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  // Only super_admin can modify super_admin permissions
  if (user.role === 'super_admin' && req.user.role !== 'super_admin') {
    return res.status(403).json({
      success: false,
      error: 'Only super admin can modify super admin permissions'
    });
  }

  user.permissions = req.body.permissions;
  await user.save();

  res.json({
    success: true,
    message: 'User permissions updated successfully',
    data: {
      permissions: user.permissions
    }
  });
}));

// Get user statistics
router.get('/stats/overview', requirePermission('User', 'read'), asyncHandler(async (req, res) => {
  const stats = await User.aggregate([
    {
      $group: {
        _id: '$role',
        count: { $sum: 1 },
        active: {
          $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] }
        }
      }
    }
  ]);

  const totalUsers = await User.countDocuments();
  const activeUsers = await User.countDocuments({ isActive: true });
  const recentUsers = await User.countDocuments({
    createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
  });

  res.json({
    success: true,
    data: {
      totalUsers,
      activeUsers,
      recentUsers,
      byRole: stats
    }
  });
}));

module.exports = router;