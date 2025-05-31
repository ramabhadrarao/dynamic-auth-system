// File: routes/admin.js
// Complete admin panel routes

const express = require('express');
const mongoose = require('mongoose');
const User = require('../models/User');
const ModelSchema = require('../models/ModelSchema');
const Attachment = require('../models/Attachment');
const { Permission, Role, Policy } = require('../models/Permission');
const { requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// Middleware to add common data to all admin routes
router.use(asyncHandler(async (req, res, next) => {
  // Get dynamic models for navigation
  const activeModels = await ModelSchema.find({ status: 'active' })
    .select('name displayName ui')
    .sort('displayName');
  
  res.locals.dynamicModels = activeModels;
  res.locals.currentPath = req.path;
  res.locals.user = req.user;
  res.locals.moment = require('moment');
  
  next();
}));

// Dashboard
router.get('/dashboard', asyncHandler(async (req, res) => {
  // Get dashboard statistics
  const stats = {
    users: await User.countDocuments({ isActive: true }),
    models: await ModelSchema.countDocuments({ status: 'active' }),
    files: await Attachment.countDocuments(),
    permissions: await Permission.countDocuments({ isActive: true })
  };
  
  // Get recent activities
  const recentUsers = await User.find({ isActive: true })
    .sort({ createdAt: -1 })
    .limit(5)
    .select('username email fullName createdAt role');
  
  const recentFiles = await Attachment.find()
    .sort({ createdAt: -1 })
    .limit(5)
    .populate('uploadedBy', 'username fullName')
    .select('originalName size mimetype createdAt uploadedBy');
  
  res.render('admin/dashboard', {
    title: 'Dashboard',
    stats,
    recentUsers,
    recentFiles
  });
}));

// Users management
router.get('/users', requireRole(['admin', 'super_admin']), asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 10;
  const skip = (page - 1) * limit;
  
  const filter = {};
  if (req.query.role) {
    filter.role = req.query.role;
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
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);
  
  res.render('admin/users/list', {
    title: 'Users',
    users,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    },
    filters: req.query
  });
}));

// User detail
router.get('/users/:id', requireRole(['admin', 'super_admin']), asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id)
    .select('-password -refreshTokens')
    .populate('avatar');
  
  if (!user) {
    return res.status(404).render('error', {
      title: 'User Not Found',
      message: 'The user you are looking for does not exist.',
      error: { status: 404 }
    });
  }
  
  res.render('admin/users/detail', {
    title: `User: ${user.fullName}`,
    targetUser: user
  });
}));

// User create form
router.get('/users/new', requireRole(['admin', 'super_admin']), (req, res) => {
  res.render('admin/users/form', {
    title: 'Create New User',
    isEdit: false
  });
});

// User edit form
router.get('/users/:id/edit', requireRole(['admin', 'super_admin']), asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id)
    .select('-password -refreshTokens');
  
  if (!user) {
    return res.status(404).render('error', {
      title: 'User Not Found',
      message: 'The user you are looking for does not exist.',
      error: { status: 404 }
    });
  }
  
  res.render('admin/users/form', {
    title: `Edit User: ${user.fullName}`,
    targetUser: user,
    isEdit: true
  });
}));

// Models management
router.get('/models', requireRole(['admin', 'super_admin']), asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 10;
  const skip = (page - 1) * limit;
  
  const filter = {};
  if (req.query.status) {
    filter.status = req.query.status;
  }
  
  const total = await ModelSchema.countDocuments(filter);
  const models = await ModelSchema.find(filter)
    .populate('createdBy', 'username fullName')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);
  
  res.render('admin/models/list', {
    title: 'Models',
    models,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    },
    filters: req.query
  });
}));

// Model detail
router.get('/models/:id', requireRole(['admin', 'super_admin']), asyncHandler(async (req, res) => {
  const model = await ModelSchema.findById(req.params.id)
    .populate('createdBy', 'username fullName')
    .populate('updatedBy', 'username fullName');
  
  if (!model) {
    return res.status(404).render('error', {
      title: 'Model Not Found',
      message: 'The model you are looking for does not exist.',
      error: { status: 404 }
    });
  }
  
  // Get record count if model is active
  let recordCount = 0;
  if (model.status === 'active') {
    try {
      const Model = mongoose.models[model.name];
      if (Model) {
        recordCount = await Model.countDocuments();
      }
    } catch (error) {
      console.error('Error getting record count:', error);
    }
  }
  
  res.render('admin/models/detail', {
    title: `Model: ${model.displayName}`,
    model,
    recordCount
  });
}));

// Model builder
router.get('/models/new', requireRole(['admin', 'super_admin']), (req, res) => {
  res.render('admin/models/builder', {
    title: 'Create New Model',
    isEdit: false
  });
});

// Model editor
router.get('/models/:id/edit', requireRole(['admin', 'super_admin']), asyncHandler(async (req, res) => {
  const model = await ModelSchema.findById(req.params.id);
  
  if (!model) {
    return res.status(404).render('error', {
      title: 'Model Not Found',
      message: 'The model you are looking for does not exist.',
      error: { status: 404 }
    });
  }
  
  res.render('admin/models/builder', {
    title: `Edit Model: ${model.displayName}`,
    model,
    isEdit: true
  });
}));

// Permissions management
router.get('/permissions', requireRole(['admin', 'super_admin']), asyncHandler(async (req, res) => {
  const permissions = await Permission.find({ isActive: true })
    .populate('createdBy', 'username fullName')
    .sort('resource action');
  
  const roles = await Role.find({ isActive: true })
    .populate('permissions')
    .populate('createdBy', 'username fullName')
    .sort('level name');
  
  const policies = await Policy.find({ isActive: true })
    .populate('createdBy', 'username fullName')
    .sort('priority name');
  
  res.render('admin/permissions/list', {
    title: 'Permissions & Roles',
    permissions,
    roles,
    policies
  });
}));

// Files management
router.get('/files', asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const skip = (page - 1) * limit;
  
  const filter = {};
  if (req.query.category) {
    filter.category = req.query.category;
  }
  if (req.query.search) {
    filter.$or = [
      { originalName: { $regex: req.query.search, $options: 'i' } },
      { filename: { $regex: req.query.search, $options: 'i' } }
    ];
  }
  
  // Non-admin users can only see their own files or public files
  if (req.user.role !== 'super_admin' && req.user.role !== 'admin') {
    filter.$or = [
      { uploadedBy: req.user._id },
      { isPublic: true }
    ];
  }
  
  const total = await Attachment.countDocuments(filter);
  const files = await Attachment.find(filter)
    .populate('uploadedBy', 'username fullName')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);
  
  res.render('admin/files/list', {
    title: 'Files',
    files,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    },
    filters: req.query
  });
}));

// Settings
router.get('/settings', (req, res) => {
  res.render('admin/settings', {
    title: 'Settings'
  });
});

// Profile
router.get('/profile', (req, res) => {
  res.render('admin/profile', {
    title: 'My Profile'
  });
});

// Help page
router.get('/help', (req, res) => {
  res.render('admin/help', {
    title: 'Help & Documentation'
  });
});

// API Documentation
router.get('/docs', (req, res) => {
  res.render('admin/docs', {
    title: 'API Documentation'
  });
});

// System status
router.get('/status', requireRole(['admin', 'super_admin']), asyncHandler(async (req, res) => {
  const systemStats = {
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    platform: process.platform,
    nodeVersion: process.version,
    environment: process.env.NODE_ENV
  };
  
  const dbStats = {
    connected: mongoose.connection.readyState === 1,
    name: mongoose.connection.name,
    host: mongoose.connection.host,
    port: mongoose.connection.port
  };
  
  res.render('admin/status', {
    title: 'System Status',
    systemStats,
    dbStats
  });
}));

// Dynamic model routes
router.get('/:model', asyncHandler(async (req, res, next) => {
  const modelName = req.params.model;
  
  // Check if this is a dynamic model
  const modelSchema = await ModelSchema.findOne({ 
    name: { $regex: new RegExp('^' + modelName + '$', 'i') }, 
    status: 'active' 
  });
  
  if (!modelSchema) {
    return next(); // Pass to 404 handler
  }
  
  // Check if user has permission to access this model
  if (!req.user.hasPermission(modelSchema.name, 'read') && req.user.role !== 'super_admin') {
    return res.status(403).render('error', {
      title: 'Access Denied',
      message: `You don't have permission to access ${modelSchema.displayName}`,
      error: { status: 403 }
    });
  }
  
  const Model = mongoose.models[modelSchema.name];
  if (!Model) {
    return res.status(500).render('error', {
      title: 'Model Error',
      message: 'Model is not properly loaded',
      error: { status: 500 }
    });
  }
  
  // Get records with pagination
  const page = parseInt(req.query.page) || 1;
  const limit = modelSchema.ui.listView.pageSize || 10;
  const skip = (page - 1) * limit;
  
  let filter = {};
  
  // Apply user-based filtering
  if (req.user.role !== 'super_admin') {
    const userPermission = req.user.permissions.find(p => p.resource === modelSchema.name);
    if (userPermission && userPermission.conditions) {
      Object.entries(userPermission.conditions).forEach(([key, value]) => {
        if (value === '${user.id}') {
          filter[key] = req.user._id;
        } else if (value === '${user.department}') {
          filter[key] = req.user.department;
        }
      });
    }
  }
  
  // Apply search
  if (req.query.search) {
    const searchFields = modelSchema.fields
      .filter(field => field.searchable && field.type === 'String')
      .map(field => field.name);
    
    if (searchFields.length > 0) {
      filter.$or = searchFields.map(field => ({
        [field]: { $regex: req.query.search, $options: 'i' }
      }));
    }
  }
  
  const total = await Model.countDocuments(filter);
  const records = await Model.find(filter)
    .sort({ [modelSchema.ui.listView.sortBy || 'createdAt']: 
           modelSchema.ui.listView.sortOrder === 'asc' ? 1 : -1 })
    .skip(skip)
    .limit(limit)
    .lean();
  
  res.render('admin/dynamic/list', {
    title: modelSchema.displayName,
    modelSchema,
    records,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    },
    search: req.query.search
  });
}));

// Dynamic model create form
router.get('/:model/new', asyncHandler(async (req, res, next) => {
  const modelName = req.params.model;
  
  const modelSchema = await ModelSchema.findOne({ 
    name: { $regex: new RegExp('^' + modelName + '$', 'i') }, 
    status: 'active' 
  });
  
  if (!modelSchema) {
    return next();
  }
  
  if (!req.user.hasPermission(modelSchema.name, 'create') && req.user.role !== 'super_admin') {
    return res.status(403).render('error', {
      title: 'Access Denied',
      message: `You don't have permission to create ${modelSchema.displayName}`,
      error: { status: 403 }
    });
  }
  
  res.render('admin/dynamic/form', {
    title: `Create ${modelSchema.displayName}`,
    modelSchema,
    isEdit: false
  });
}));

// Dynamic model detail
router.get('/:model/:id', asyncHandler(async (req, res, next) => {
  const modelName = req.params.model;
  const recordId = req.params.id;
  
  const modelSchema = await ModelSchema.findOne({ 
    name: { $regex: new RegExp('^' + modelName + '$', 'i') }, 
    status: 'active' 
  });
  
  if (!modelSchema) {
    return next();
  }
  
  if (!req.user.hasPermission(modelSchema.name, 'read') && req.user.role !== 'super_admin') {
    return res.status(403).render('error', {
      title: 'Access Denied',
      message: `You don't have permission to view ${modelSchema.displayName}`,
      error: { status: 403 }
    });
  }
  
  const Model = mongoose.models[modelSchema.name];
  let filter = { _id: recordId };
  
  // Apply user-based filtering
  if (req.user.role !== 'super_admin') {
    const userPermission = req.user.permissions.find(p => p.resource === modelSchema.name);
    if (userPermission && userPermission.conditions) {
      Object.entries(userPermission.conditions).forEach(([key, value]) => {
        if (value === '${user.id}') {
          filter[key] = req.user._id;
        } else if (value === '${user.department}') {
          filter[key] = req.user.department;
        }
      });
    }
  }
  
  const record = await Model.findOne(filter);
  
  if (!record) {
    return res.status(404).render('error', {
      title: 'Record Not Found',
      message: 'The record you are looking for does not exist.',
      error: { status: 404 }
    });
  }
  
  res.render('admin/dynamic/detail', {
    title: `${modelSchema.displayName} Details`,
    modelSchema,
    record
  });
}));

// Dynamic model edit form
router.get('/:model/:id/edit', asyncHandler(async (req, res, next) => {
  const modelName = req.params.model;
  const recordId = req.params.id;
  
  const modelSchema = await ModelSchema.findOne({ 
    name: { $regex: new RegExp('^' + modelName + '$', 'i') }, 
    status: 'active' 
  });
  
  if (!modelSchema) {
    return next();
  }
  
  if (!req.user.hasPermission(modelSchema.name, 'update') && req.user.role !== 'super_admin') {
    return res.status(403).render('error', {
      title: 'Access Denied',
      message: `You don't have permission to edit ${modelSchema.displayName}`,
      error: { status: 403 }
    });
  }
  
  const Model = mongoose.models[modelSchema.name];
  let filter = { _id: recordId };
  
  // Apply user-based filtering
  if (req.user.role !== 'super_admin') {
    const userPermission = req.user.permissions.find(p => p.resource === modelSchema.name);
    if (userPermission && userPermission.conditions) {
      Object.entries(userPermission.conditions).forEach(([key, value]) => {
        if (value === '${user.id}') {
          filter[key] = req.user._id;
        } else if (value === '${user.department}') {
          filter[key] = req.user.department;
        }
      });
    }
  }
  
  const record = await Model.findOne(filter);
  
  if (!record) {
    return res.status(404).render('error', {
      title: 'Record Not Found',
      message: 'The record you are looking for does not exist.',
      error: { status: 404 }
    });
  }
  
  res.render('admin/dynamic/form', {
    title: `Edit ${modelSchema.displayName}`,
    modelSchema,
    record,
    isEdit: true
  });
}));

module.exports = router;