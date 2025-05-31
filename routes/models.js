// File: routes/models.js
// Routes for dynamic model management

const express = require('express');
const { body, validationResult } = require('express-validator');
const ModelSchema = require('../models/ModelSchema');
const dynamicModelService = require('../services/dynamicModelService');
const { requireRole, requirePermission } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// Get all model schemas
router.get('/', requirePermission('ModelSchema', 'read'), asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;
  
  const filter = {};
  if (req.query.status) {
    filter.status = req.query.status;
  }
  
  const total = await ModelSchema.countDocuments(filter);
  const schemas = await ModelSchema.find(filter)
    .populate('createdBy', 'username email fullName')
    .populate('updatedBy', 'username email fullName')
    .skip(skip)
    .limit(limit)
    .sort({ createdAt: -1 });
  
  res.json({
    schemas,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }
  });
}));

// Get single model schema
router.get('/:id', requirePermission('ModelSchema', 'read'), asyncHandler(async (req, res) => {
  const schema = await ModelSchema.findById(req.params.id)
    .populate('createdBy', 'username email fullName')
    .populate('updatedBy', 'username email fullName');
  
  if (!schema) {
    return res.status(404).json({ error: 'Model schema not found' });
  }
  
  res.json({ schema });
}));

// Create new model schema
router.post('/', requirePermission('ModelSchema', 'create'), [
  body('name')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Name is required and must be less than 50 characters')
    .matches(/^[A-Z][a-zA-Z0-9]*$/)
    .withMessage('Name must start with uppercase letter and contain only letters and numbers'),
  body('displayName')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Display name is required and must be less than 100 characters'),
  body('fields')
    .isArray({ min: 1 })
    .withMessage('At least one field is required'),
  body('fields.*.name')
    .trim()
    .isLength({ min: 1 })
    .withMessage('Field name is required'),
  body('fields.*.type')
    .isIn(['String', 'Number', 'Date', 'Boolean', 'ObjectId', 'Array', 'Mixed', 'Buffer', 'Decimal128', 'Map'])
    .withMessage('Invalid field type')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  // Check if model name already exists
  const existingSchema = await ModelSchema.findOne({ name: req.body.name });
  if (existingSchema) {
    return res.status(400).json({
      error: 'Model with this name already exists'
    });
  }

  const schemaData = {
    ...req.body,
    createdBy: req.user._id,
    status: 'draft'
  };

  const modelSchema = new ModelSchema(schemaData);
  
  // Validate fields
  const fieldErrors = modelSchema.validateFields();
  if (fieldErrors.length > 0) {
    return res.status(400).json({
      error: 'Field validation failed',
      errors: fieldErrors
    });
  }

  await modelSchema.save();
  
  res.status(201).json({
    message: 'Model schema created successfully',
    schema: modelSchema
  });
}));

// Update model schema
router.put('/:id', requirePermission('ModelSchema', 'update'), [
  body('displayName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Display name must be between 1 and 100 characters'),
  body('fields')
    .optional()
    .isArray({ min: 1 })
    .withMessage('At least one field is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  const schema = await ModelSchema.findById(req.params.id);
  if (!schema) {
    return res.status(404).json({ error: 'Model schema not found' });
  }

  // Don't allow name changes if model is active
  if (schema.status === 'active' && req.body.name && req.body.name !== schema.name) {
    return res.status(400).json({
      error: 'Cannot change name of active model'
    });
  }

  const allowedUpdates = ['displayName', 'description', 'fields', 'options', 'indexes', 'virtuals', 'methods', 'statics', 'middleware', 'permissions', 'ui'];
  const updates = {};
  
  Object.keys(req.body).forEach(key => {
    if (allowedUpdates.includes(key)) {
      updates[key] = req.body[key];
    }
  });

  updates.updatedBy = req.user._id;
  updates.version = incrementVersion(schema.version);

  Object.assign(schema, updates);
  
  // Validate fields if updated
  if (updates.fields) {
    const fieldErrors = schema.validateFields();
    if (fieldErrors.length > 0) {
      return res.status(400).json({
        error: 'Field validation failed',
        errors: fieldErrors
      });
    }
  }

  await schema.save();

  // Update dynamic model if active
  if (schema.status === 'active') {
    try {
      await dynamicModelService.updateModel(schema);
    } catch (error) {
      console.error('Error updating dynamic model:', error);
      return res.status(500).json({
        error: 'Schema updated but model reload failed',
        details: error.message
      });
    }
  }

  res.json({
    message: 'Model schema updated successfully',
    schema
  });
}));

// Activate model schema (deploy to runtime)
router.post('/:id/activate', requirePermission('ModelSchema', 'manage'), asyncHandler(async (req, res) => {
  const schema = await ModelSchema.findById(req.params.id);
  if (!schema) {
    return res.status(404).json({ error: 'Model schema not found' });
  }

  if (schema.status === 'active') {
    return res.status(400).json({ error: 'Model is already active' });
  }

  // Validate schema before activation
  const fieldErrors = schema.validateFields();
  if (fieldErrors.length > 0) {
    return res.status(400).json({
      error: 'Cannot activate model with field errors',
      errors: fieldErrors
    });
  }

  try {
    // Create dynamic model
    await dynamicModelService.createModel(schema);
    
    // Update status
    schema.status = 'active';
    schema.updatedBy = req.user._id;
    await schema.save();

    res.json({
      message: 'Model activated successfully',
      schema
    });
  } catch (error) {
    console.error('Error activating model:', error);
    res.status(500).json({
      error: 'Failed to activate model',
      details: error.message
    });
  }
}));

// Deactivate model schema
router.post('/:id/deactivate', requirePermission('ModelSchema', 'manage'), asyncHandler(async (req, res) => {
  const schema = await ModelSchema.findById(req.params.id);
  if (!schema) {
    return res.status(404).json({ error: 'Model schema not found' });
  }

  if (schema.status !== 'active') {
    return res.status(400).json({ error: 'Model is not active' });
  }

  try {
    // Remove dynamic model
    await dynamicModelService.deleteModel(schema.name);
    
    // Update status
    schema.status = 'draft';
    schema.updatedBy = req.user._id;
    await schema.save();

    res.json({
      message: 'Model deactivated successfully',
      schema
    });
  } catch (error) {
    console.error('Error deactivating model:', error);
    res.status(500).json({
      error: 'Failed to deactivate model',
      details: error.message
    });
  }
}));

// Delete model schema
router.delete('/:id', requirePermission('ModelSchema', 'delete'), asyncHandler(async (req, res) => {
  const schema = await ModelSchema.findById(req.params.id);
  if (!schema) {
    return res.status(404).json({ error: 'Model schema not found' });
  }

  // Don't allow deletion of active models
  if (schema.status === 'active') {
    return res.status(400).json({
      error: 'Cannot delete active model. Deactivate it first.'
    });
  }

  await schema.deleteOne();

  res.json({
    message: 'Model schema deleted successfully'
  });
}));

// Get model statistics
router.get('/:id/stats', requirePermission('ModelSchema', 'read'), asyncHandler(async (req, res) => {
  const schema = await ModelSchema.findById(req.params.id);
  if (!schema) {
    return res.status(404).json({ error: 'Model schema not found' });
  }

  const stats = {
    fieldsCount: schema.fields.length,
    indexesCount: schema.indexes ? schema.indexes.length : 0,
    virtualsCount: schema.virtuals ? schema.virtuals.length : 0,
    methodsCount: schema.methods ? schema.methods.length : 0,
    staticsCount: schema.statics ? schema.statics.length : 0,
    middlewareCount: schema.middleware ? schema.middleware.length : 0,
    status: schema.status,
    version: schema.version
  };

  // Get record count if model is active
  if (schema.status === 'active') {
    try {
      const Model = require('mongoose').models[schema.name];
      if (Model) {
        stats.recordsCount = await Model.countDocuments();
      }
    } catch (error) {
      console.error('Error getting record count:', error);
      stats.recordsCount = 0;
    }
  }

  res.json({ stats });
}));

// Clone model schema
router.post('/:id/clone', requirePermission('ModelSchema', 'create'), [
  body('name')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Name is required and must be less than 50 characters')
    .matches(/^[A-Z][a-zA-Z0-9]*$/)
    .withMessage('Name must start with uppercase letter and contain only letters and numbers'),
  body('displayName')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Display name is required and must be less than 100 characters')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  const originalSchema = await ModelSchema.findById(req.params.id);
  if (!originalSchema) {
    return res.status(404).json({ error: 'Model schema not found' });
  }

  // Check if new name already exists
  const existingSchema = await ModelSchema.findOne({ name: req.body.name });
  if (existingSchema) {
    return res.status(400).json({
      error: 'Model with this name already exists'
    });
  }

  // Create clone
  const cloneData = originalSchema.toObject();
  delete cloneData._id;
  delete cloneData.createdAt;
  delete cloneData.updatedAt;
  
  cloneData.name = req.body.name;
  cloneData.displayName = req.body.displayName;
  cloneData.status = 'draft';
  cloneData.version = '1.0.0';
  cloneData.createdBy = req.user._id;
  cloneData.updatedBy = req.user._id;

  const clonedSchema = new ModelSchema(cloneData);
  await clonedSchema.save();

  res.status(201).json({
    message: 'Model schema cloned successfully',
    schema: clonedSchema
  });
}));

// Export model schema
router.get('/:id/export', requirePermission('ModelSchema', 'read'), asyncHandler(async (req, res) => {
  const schema = await ModelSchema.findById(req.params.id);
  if (!schema) {
    return res.status(404).json({ error: 'Model schema not found' });
  }

  const exportData = schema.toObject();
  delete exportData._id;
  delete exportData.createdAt;
  delete exportData.updatedAt;
  delete exportData.createdBy;
  delete exportData.updatedBy;
  delete exportData.__v;

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${schema.name}-schema.json"`);
  res.json(exportData);
}));

// Import model schema
router.post('/import', requirePermission('ModelSchema', 'create'), asyncHandler(async (req, res) => {
  const importData = req.body;

  if (!importData.name || !importData.displayName || !importData.fields) {
    return res.status(400).json({
      error: 'Invalid import data. Required fields: name, displayName, fields'
    });
  }

  // Check if model name already exists
  const existingSchema = await ModelSchema.findOne({ name: importData.name });
  if (existingSchema) {
    return res.status(400).json({
      error: 'Model with this name already exists'
    });
  }

  // Create new schema from import data
  const schemaData = {
    ...importData,
    status: 'draft',
    version: '1.0.0',
    createdBy: req.user._id
  };

  const modelSchema = new ModelSchema(schemaData);
  
  // Validate fields
  const fieldErrors = modelSchema.validateFields();
  if (fieldErrors.length > 0) {
    return res.status(400).json({
      error: 'Field validation failed',
      errors: fieldErrors
    });
  }

  await modelSchema.save();

  res.status(201).json({
    message: 'Model schema imported successfully',
    schema: modelSchema
  });
}));

// Get field types and options
router.get('/field-types', asyncHandler(async (req, res) => {
  const fieldTypes = [
    { value: 'String', label: 'Text', inputTypes: ['text', 'email', 'password', 'url', 'tel', 'textarea'] },
    { value: 'Number', label: 'Number', inputTypes: ['number'] },
    { value: 'Date', label: 'Date', inputTypes: ['date', 'datetime-local', 'time'] },
    { value: 'Boolean', label: 'Boolean', inputTypes: ['checkbox', 'radio'] },
    { value: 'ObjectId', label: 'Reference', inputTypes: ['select'] },
    { value: 'Array', label: 'Array', inputTypes: ['select'] },
    { value: 'Mixed', label: 'Mixed', inputTypes: ['textarea'] }
  ];

  const validationRules = [
    { rule: 'required', label: 'Required', applicable: ['all'] },
    { rule: 'unique', label: 'Unique', applicable: ['all'] },
    { rule: 'minlength', label: 'Minimum Length', applicable: ['String'] },
    { rule: 'maxlength', label: 'Maximum Length', applicable: ['String'] },
    { rule: 'min', label: 'Minimum Value', applicable: ['Number', 'Date'] },
    { rule: 'max', label: 'Maximum Value', applicable: ['Number', 'Date'] },
    { rule: 'match', label: 'Pattern (Regex)', applicable: ['String'] },
    { rule: 'enum', label: 'Allowed Values', applicable: ['String', 'Number'] }
  ];

  res.json({
    fieldTypes,
    validationRules
  });
}));

// Helper function to increment version
function incrementVersion(currentVersion) {
  const parts = currentVersion.split('.');
  const patch = parseInt(parts[2]) + 1;
  return `${parts[0]}.${parts[1]}.${patch}`;
}

module.exports = router;