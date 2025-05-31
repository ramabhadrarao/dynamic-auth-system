// File: middleware/dynamicModel.js
// Middleware for dynamic model loading and management

const mongoose = require('mongoose');
const ModelSchema = require('../models/ModelSchema');

// Middleware to load dynamic models for each request
const dynamicModelLoader = async (req, res, next) => {
  try {
    // Attach dynamic models to request object
    req.dynamicModels = mongoose.models || {};
    
    // Add helper methods
    req.getDynamicModel = (modelName) => {
      return mongoose.models[modelName];
    };
    
    req.getModelSchema = async (modelName) => {
      return await ModelSchema.findOne({ name: modelName, status: 'active' });
    };
    
    req.listDynamicModels = () => {
      const dynamicModels = {};
      Object.keys(mongoose.models).forEach(modelName => {
        if (!['User', 'ModelSchema', 'Attachment', 'Permission', 'Role', 'Policy'].includes(modelName)) {
          dynamicModels[modelName] = mongoose.models[modelName];
        }
      });
      return dynamicModels;
    };
    
    next();
  } catch (error) {
    console.error('Dynamic model loader error:', error);
    next(error);
  }
};

// Middleware to validate dynamic model access
const validateModelAccess = (req, res, next) => {
  const modelName = req.params.model || req.body.model;
  
  if (!modelName) {
    return res.status(400).json({ error: 'Model name is required' });
  }
  
  const Model = req.getDynamicModel(modelName);
  if (!Model) {
    return res.status(404).json({ error: `Model '${modelName}' not found` });
  }
  
  req.targetModel = Model;
  req.modelName = modelName;
  next();
};

// Middleware to check model permissions
const checkModelPermissions = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const modelName = req.modelName;
    const action = getActionFromMethod(req.method);
    
    // Super admin has all permissions
    if (req.user.role === 'super_admin') {
      return next();
    }
    
    // Get model schema to check permissions
    const modelSchema = await req.getModelSchema(modelName);
    if (!modelSchema) {
      return res.status(404).json({ error: 'Model schema not found' });
    }
    
    // Check if user has permission for this action on this model
    const hasPermission = checkUserModelPermission(req.user, modelSchema, action);
    
    if (!hasPermission) {
      return res.status(403).json({ 
        error: `Permission denied: ${action} on ${modelName}` 
      });
    }
    
    req.modelSchema = modelSchema;
    next();
  } catch (error) {
    console.error('Model permission check error:', error);
    next(error);
  }
};

// Middleware to apply field-level filtering based on permissions
const applyFieldFiltering = async (req, res, next) => {
  try {
    if (!req.modelSchema || !req.user) {
      return next();
    }
    
    const userRole = req.user.role;
    const action = getActionFromMethod(req.method);
    
    // Get allowed fields for this user/role/action
    const allowedFields = getAllowedFields(req.modelSchema, userRole, action);
    
    // Filter request body for create/update operations
    if (['POST', 'PUT', 'PATCH'].includes(req.method) && req.body) {
      req.body = filterObjectFields(req.body, allowedFields);
    }
    
    // Store allowed fields for response filtering
    req.allowedFields = allowedFields;
    
    next();
  } catch (error) {
    console.error('Field filtering error:', error);
    next(error);
  }
};

// Middleware to apply data filtering based on ABAC rules
const applyDataFiltering = async (req, res, next) => {
  try {
    if (!req.modelSchema || !req.user) {
      return next();
    }
    
    const action = getActionFromMethod(req.method);
    const filter = getDataFilter(req.modelSchema, req.user, action);
    
    // Apply filter to query operations
    if (['GET'].includes(req.method)) {
      req.dataFilter = filter;
    }
    
    // For update/delete operations, check if the resource matches the filter
    if (['PUT', 'PATCH', 'DELETE'].includes(req.method) && req.params.id) {
      const document = await req.targetModel.findById(req.params.id);
      if (document && !matchesFilter(document, filter)) {
        return res.status(403).json({ 
          error: 'Access denied to this resource' 
        });
      }
    }
    
    next();
  } catch (error) {
    console.error('Data filtering error:', error);
    next(error);
  }
};

// Helper function to get action from HTTP method
const getActionFromMethod = (method) => {
  switch (method.toUpperCase()) {
    case 'GET':
      return 'read';
    case 'POST':
      return 'create';
    case 'PUT':
    case 'PATCH':
      return 'update';
    case 'DELETE':
      return 'delete';
    default:
      return 'execute';
  }
};

// Helper function to check user permission on model
const checkUserModelPermission = (user, modelSchema, action) => {
  // Check model-level permissions
  const modelPermissions = modelSchema.permissions[action];
  if (!modelPermissions || modelPermissions.length === 0) {
    return false;
  }
  
  // Check if user's role has permission
  const hasRolePermission = modelPermissions.some(perm => 
    perm.role === user.role || perm.role === '*'
  );
  
  return hasRolePermission;
};

// Helper function to get allowed fields for user
const getAllowedFields = (modelSchema, userRole, action) => {
  const allowedFields = [];
  
  modelSchema.fields.forEach(field => {
    // Check if field should be shown for this action
    const showField = (action === 'read' && field.showInDetail) ||
                     (action === 'create' && field.showInForm) ||
                     (action === 'update' && field.showInForm);
    
    if (showField) {
      allowedFields.push(field.name);
    }
  });
  
  return allowedFields;
};

// Helper function to get data filter for user
const getDataFilter = (modelSchema, user, action) => {
  const filter = {};
  
  // Get permissions for this action
  const permissions = modelSchema.permissions[action];
  if (!permissions || permissions.length === 0) {
    return { _id: null }; // No access
  }
  
  // Find matching permission for user's role
  const userPermission = permissions.find(perm => 
    perm.role === user.role || perm.role === '*'
  );
  
  if (!userPermission) {
    return { _id: null }; // No access
  }
  
  // Apply conditions
  if (userPermission.conditions && Object.keys(userPermission.conditions).length > 0) {
    Object.entries(userPermission.conditions).forEach(([key, value]) => {
      if (value === '${user.id}') {
        filter[key] = user._id;
      } else if (value === '${user.department}') {
        filter[key] = user.department;
      } else {
        filter[key] = value;
      }
    });
  }
  
  return filter;
};

// Helper function to filter object fields
const filterObjectFields = (obj, allowedFields) => {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return obj;
  }
  
  const filtered = {};
  allowedFields.forEach(field => {
    if (obj.hasOwnProperty(field)) {
      filtered[field] = obj[field];
    }
  });
  
  return filtered;
};

// Helper function to check if document matches filter
const matchesFilter = (document, filter) => {
  if (!filter || Object.keys(filter).length === 0) {
    return true;
  }
  
  for (const [key, value] of Object.entries(filter)) {
    if (document[key] !== value && document[key]?.toString() !== value?.toString()) {
      return false;
    }
  }
  
  return true;
};

// Middleware to validate dynamic model data
const validateModelData = async (req, res, next) => {
  try {
    if (!req.modelSchema || !req.body) {
      return next();
    }
    
    const errors = {};
    const data = req.body;
    
    // Validate each field
    req.modelSchema.fields.forEach(fieldDef => {
      const fieldName = fieldDef.name;
      const fieldValue = data[fieldName];
      
      // Check required fields
      if (fieldDef.required && (fieldValue === undefined || fieldValue === null || fieldValue === '')) {
        errors[fieldName] = `${fieldDef.label || fieldName} is required`;
        return;
      }
      
      // Skip validation if field is not provided and not required
      if (fieldValue === undefined || fieldValue === null) {
        return;
      }
      
      // Type validation
      if (!validateFieldType(fieldValue, fieldDef.type)) {
        errors[fieldName] = `${fieldDef.label || fieldName} must be of type ${fieldDef.type}`;
        return;
      }
      
      // Enum validation
      if (fieldDef.enum && fieldDef.enum.length > 0 && !fieldDef.enum.includes(fieldValue)) {
        errors[fieldName] = `${fieldDef.label || fieldName} must be one of: ${fieldDef.enum.join(', ')}`;
        return;
      }
      
      // String validations
      if (fieldDef.type === 'String' && typeof fieldValue === 'string') {
        if (fieldDef.minlength && fieldValue.length < fieldDef.minlength) {
          errors[fieldName] = `${fieldDef.label || fieldName} must be at least ${fieldDef.minlength} characters`;
          return;
        }
        
        if (fieldDef.maxlength && fieldValue.length > fieldDef.maxlength) {
          errors[fieldName] = `${fieldDef.label || fieldName} cannot exceed ${fieldDef.maxlength} characters`;
          return;
        }
        
        if (fieldDef.match && !new RegExp(fieldDef.match).test(fieldValue)) {
          errors[fieldName] = `${fieldDef.label || fieldName} format is invalid`;
          return;
        }
      }
      
      // Number validations
      if (fieldDef.type === 'Number' && typeof fieldValue === 'number') {
        if (fieldDef.min !== undefined && fieldValue < fieldDef.min) {
          errors[fieldName] = `${fieldDef.label || fieldName} must be at least ${fieldDef.min}`;
          return;
        }
        
        if (fieldDef.max !== undefined && fieldValue > fieldDef.max) {
          errors[fieldName] = `${fieldDef.label || fieldName} cannot exceed ${fieldDef.max}`;
          return;
        }
      }
    });
    
    if (Object.keys(errors).length > 0) {
      return res.status(400).json({
        error: 'Validation failed',
        errors: errors
      });
    }
    
    next();
  } catch (error) {
    console.error('Model data validation error:', error);
    next(error);
  }
};

// Helper function to validate field type
const validateFieldType = (value, expectedType) => {
  switch (expectedType) {
    case 'String':
      return typeof value === 'string';
    case 'Number':
      return typeof value === 'number' && !isNaN(value);
    case 'Boolean':
      return typeof value === 'boolean';
    case 'Date':
      return value instanceof Date || !isNaN(Date.parse(value));
    case 'ObjectId':
      return mongoose.Types.ObjectId.isValid(value);
    case 'Array':
      return Array.isArray(value);
    case 'Mixed':
      return true; // Mixed accepts any type
    default:
      return true;
  }
};

module.exports = {
  dynamicModelLoader,
  validateModelAccess,
  checkModelPermissions,
  applyFieldFiltering,
  applyDataFiltering,
  validateModelData
};