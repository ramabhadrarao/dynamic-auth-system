// File: routes/dynamic.js
// Dynamic routes for generated models

const express = require('express');
const mongoose = require('mongoose');
const { 
  validateModelAccess, 
  checkModelPermissions, 
  applyFieldFiltering, 
  applyDataFiltering, 
  validateModelData 
} = require('../middleware/dynamicModel');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// Middleware chain for all dynamic routes
const dynamicMiddleware = [
  validateModelAccess,
  checkModelPermissions,
  applyFieldFiltering,
  applyDataFiltering
];

// Get all records for a model
router.get('/:model', dynamicMiddleware, asyncHandler(async (req, res) => {
  const Model = req.targetModel;
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 10, 100); // Max 100 records per page
  const skip = (page - 1) * limit;
  
  // Build query filter
  let filter = req.dataFilter || {};
  
  // Add search functionality
  if (req.query.search && req.modelSchema) {
    const searchFields = req.modelSchema.fields
      .filter(field => field.searchable && field.type === 'String')
      .map(field => field.name);
    
    if (searchFields.length > 0) {
      const searchConditions = searchFields.map(field => ({
        [field]: { $regex: req.query.search, $options: 'i' }
      }));
      filter = {
        ...filter,
        $or: searchConditions
      };
    }
  }
  
  // Add field-specific filters
  Object.keys(req.query).forEach(key => {
    if (key.startsWith('filter_')) {
      const fieldName = key.replace('filter_', '');
      const fieldDef = req.modelSchema.fields.find(f => f.name === fieldName);
      
      if (fieldDef && fieldDef.filterable) {
        filter[fieldName] = req.query[key];
      }
    }
  });
  
  // Build sort options
  let sort = {};
  if (req.query.sort) {
    const sortField = req.query.sort.replace('-', '');
    const sortOrder = req.query.sort.startsWith('-') ? -1 : 1;
    
    const fieldDef = req.modelSchema.fields.find(f => f.name === sortField);
    if (fieldDef && fieldDef.sortable) {
      sort[sortField] = sortOrder;
    }
  } else if (req.modelSchema.ui.listView.sortBy) {
    const sortOrder = req.modelSchema.ui.listView.sortOrder === 'desc' ? -1 : 1;
    sort[req.modelSchema.ui.listView.sortBy] = sortOrder;
  } else {
    sort = { createdAt: -1 }; // Default sort
  }
  
  // Execute query
  const query = Model.find(filter);
  
  // Apply population for ObjectId fields
  if (req.modelSchema.fields) {
    req.modelSchema.fields
      .filter(field => field.type === 'ObjectId' && field.ref)
      .forEach(field => {
        query.populate(field.name, 'name title displayName');
      });
  }
  
  const total = await Model.countDocuments(filter);
  const records = await query
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean()
    .exec();
  
  // Filter response fields based on permissions
  const filteredRecords = records.map(record => 
    filterRecordFields(record, req.allowedFields)
  );
  
  res.json({
    success: true,
    data: filteredRecords,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit),
      hasNextPage: page < Math.ceil(total / limit),
      hasPrevPage: page > 1
    },
    meta: {
      model: req.modelName,
      totalRecords: total,
      searchApplied: !!req.query.search,
      filtersApplied: Object.keys(req.query).some(key => key.startsWith('filter_'))
    }
  });
}));

// Get single record by ID
router.get('/:model/:id', dynamicMiddleware, asyncHandler(async (req, res) => {
  const Model = req.targetModel;
  const recordId = req.params.id;
  
  if (!mongoose.Types.ObjectId.isValid(recordId)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid record ID'
    });
  }
  
  // Build query with data filter
  const filter = { 
    _id: recordId,
    ...req.dataFilter 
  };
  
  const query = Model.findOne(filter);
  
  // Apply population for ObjectId fields
  if (req.modelSchema.fields) {
    req.modelSchema.fields
      .filter(field => field.type === 'ObjectId' && field.ref)
      .forEach(field => {
        query.populate(field.name);
      });
  }
  
  const record = await query.lean().exec();
  
  if (!record) {
    return res.status(404).json({
      success: false,
      error: 'Record not found'
    });
  }
  
  // Filter response fields based on permissions
  const filteredRecord = filterRecordFields(record, req.allowedFields);
  
  res.json({
    success: true,
    data: filteredRecord
  });
}));

// Create new record
router.post('/:model', [...dynamicMiddleware, validateModelData], asyncHandler(async (req, res) => {
  const Model = req.targetModel;
  const data = req.body;
  
  // Add automatic fields
  if (Model.schema.paths.createdBy) {
    data.createdBy = req.user._id;
  }
  
  if (Model.schema.paths.owner) {
    data.owner = req.user._id;
  }
  
  if (Model.schema.paths.department && req.user.department) {
    data.department = req.user.department;
  }
  
  // Create new record
  const record = new Model(data);
  await record.save();
  
  // Populate references before sending response
  if (req.modelSchema.fields) {
    const populateFields = req.modelSchema.fields
      .filter(field => field.type === 'ObjectId' && field.ref)
      .map(field => field.name);
    
    if (populateFields.length > 0) {
      await record.populate(populateFields);
    }
  }
  
  // Filter response fields
  const filteredRecord = filterRecordFields(record.toObject(), req.allowedFields);
  
  res.status(201).json({
    success: true,
    message: `${req.modelSchema.displayName} created successfully`,
    data: filteredRecord
  });
}));

// Update record
router.put('/:model/:id', [...dynamicMiddleware, validateModelData], asyncHandler(async (req, res) => {
  const Model = req.targetModel;
  const recordId = req.params.id;
  const data = req.body;
  
  if (!mongoose.Types.ObjectId.isValid(recordId)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid record ID'
    });
  }
  
  // Build query with data filter
  const filter = { 
    _id: recordId,
    ...req.dataFilter 
  };
  
  const record = await Model.findOne(filter);
  
  if (!record) {
    return res.status(404).json({
      success: false,
      error: 'Record not found'
    });
  }
  
  // Add automatic fields
  if (Model.schema.paths.updatedBy) {
    data.updatedBy = req.user._id;
  }
  
  // Update record
  Object.assign(record, data);
  await record.save();
  
  // Populate references before sending response
  if (req.modelSchema.fields) {
    const populateFields = req.modelSchema.fields
      .filter(field => field.type === 'ObjectId' && field.ref)
      .map(field => field.name);
    
    if (populateFields.length > 0) {
      await record.populate(populateFields);
    }
  }
  
  // Filter response fields
  const filteredRecord = filterRecordFields(record.toObject(), req.allowedFields);
  
  res.json({
    success: true,
    message: `${req.modelSchema.displayName} updated successfully`,
    data: filteredRecord
  });
}));

// Partial update (PATCH)
router.patch('/:model/:id', [...dynamicMiddleware, validateModelData], asyncHandler(async (req, res) => {
  const Model = req.targetModel;
  const recordId = req.params.id;
  const updates = req.body;
  
  if (!mongoose.Types.ObjectId.isValid(recordId)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid record ID'
    });
  }
  
  // Build query with data filter
  const filter = { 
    _id: recordId,
    ...req.dataFilter 
  };
  
  // Add automatic fields
  if (Model.schema.paths.updatedBy) {
    updates.updatedBy = req.user._id;
  }
  
  const record = await Model.findOneAndUpdate(
    filter,
    { $set: updates },
    { new: true, runValidators: true }
  );
  
  if (!record) {
    return res.status(404).json({
      success: false,
      error: 'Record not found'
    });
  }
  
  // Populate references before sending response
  if (req.modelSchema.fields) {
    const populateFields = req.modelSchema.fields
      .filter(field => field.type === 'ObjectId' && field.ref)
      .map(field => field.name);
    
    if (populateFields.length > 0) {
      await record.populate(populateFields);
    }
  }
  
  // Filter response fields
  const filteredRecord = filterRecordFields(record.toObject(), req.allowedFields);
  
  res.json({
    success: true,
    message: `${req.modelSchema.displayName} updated successfully`,
    data: filteredRecord
  });
}));

// Delete record
router.delete('/:model/:id', dynamicMiddleware, asyncHandler(async (req, res) => {
  const Model = req.targetModel;
  const recordId = req.params.id;
  
  if (!mongoose.Types.ObjectId.isValid(recordId)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid record ID'
    });
  }
  
  // Build query with data filter
  const filter = { 
    _id: recordId,
    ...req.dataFilter 
  };
  
  const record = await Model.findOne(filter);
  
  if (!record) {
    return res.status(404).json({
      success: false,
      error: 'Record not found'
    });
  }
  
  await record.deleteOne();
  
  res.json({
    success: true,
    message: `${req.modelSchema.displayName} deleted successfully`
  });
}));

// Bulk operations
router.post('/:model/bulk', dynamicMiddleware, asyncHandler(async (req, res) => {
  const Model = req.targetModel;
  const { operation, data, filter } = req.body;
  
  if (!operation) {
    return res.status(400).json({
      success: false,
      error: 'Operation is required'
    });
  }
  
  let result;
  
  switch (operation) {
    case 'create':
      if (!Array.isArray(data)) {
        return res.status(400).json({
          success: false,
          error: 'Data must be an array for bulk create'
        });
      }
      
      // Add automatic fields to each record
      const recordsToCreate = data.map(record => {
        if (Model.schema.paths.createdBy) record.createdBy = req.user._id;
        if (Model.schema.paths.owner) record.owner = req.user._id;
        if (Model.schema.paths.department && req.user.department) {
          record.department = req.user.department;
        }
        return record;
      });
      
      result = await Model.insertMany(recordsToCreate, { ordered: false });
      break;
      
    case 'update':
      if (!data || !filter) {
        return res.status(400).json({
          success: false,
          error: 'Data and filter are required for bulk update'
        });
      }
      
      // Apply data filter for security
      const updateFilter = { ...filter, ...req.dataFilter };
      
      // Add automatic fields
      if (Model.schema.paths.updatedBy) {
        data.updatedBy = req.user._id;
      }
      
      result = await Model.updateMany(updateFilter, { $set: data });
      break;
      
    case 'delete':
      if (!filter) {
        return res.status(400).json({
          success: false,
          error: 'Filter is required for bulk delete'
        });
      }
      
      // Apply data filter for security
      const deleteFilter = { ...filter, ...req.dataFilter };
      
      result = await Model.deleteMany(deleteFilter);
      break;
      
    default:
      return res.status(400).json({
        success: false,
        error: 'Invalid operation. Supported: create, update, delete'
      });
  }
  
  res.json({
    success: true,
    message: `Bulk ${operation} completed successfully`,
    result
  });
}));

// Get model schema information
router.get('/:model/schema', dynamicMiddleware, asyncHandler(async (req, res) => {
  const schema = req.modelSchema;
  
  // Filter schema fields based on user permissions
  const allowedFields = schema.fields.filter(field => 
    req.allowedFields.includes(field.name)
  );
  
  res.json({
    success: true,
    data: {
      name: schema.name,
      displayName: schema.displayName,
      description: schema.description,
      fields: allowedFields.map(field => ({
        name: field.name,
        type: field.type,
        label: field.label,
        required: field.required,
        inputType: field.inputType,
        options: field.options,
        helpText: field.helpText,
        showInList: field.showInList,
        showInForm: field.showInForm,
        showInDetail: field.showInDetail,
        searchable: field.searchable,
        sortable: field.sortable,
        filterable: field.filterable
      })),
      ui: schema.ui,
      permissions: {
        canCreate: req.user.hasPermission(schema.name, 'create'),
        canRead: req.user.hasPermission(schema.name, 'read'),
        canUpdate: req.user.hasPermission(schema.name, 'update'),
        canDelete: req.user.hasPermission(schema.name, 'delete')
      }
    }
  });
}));

// Aggregate data
router.post('/:model/aggregate', dynamicMiddleware, asyncHandler(async (req, res) => {
  const Model = req.targetModel;
  const { pipeline } = req.body;
  
  if (!Array.isArray(pipeline)) {
    return res.status(400).json({
      success: false,
      error: 'Pipeline must be an array'
    });
  }
  
  // Add data filter as first stage if needed
  if (req.dataFilter && Object.keys(req.dataFilter).length > 0) {
    pipeline.unshift({ $match: req.dataFilter });
  }
  
  const result = await Model.aggregate(pipeline);
  
  res.json({
    success: true,
    data: result
  });
}));

// Helper function to filter record fields based on permissions
function filterRecordFields(record, allowedFields) {
  if (!allowedFields || allowedFields.length === 0) {
    return record;
  }
  
  const filtered = {};
  
  // Always include _id and timestamp fields
  const alwaysInclude = ['_id', 'createdAt', 'updatedAt'];
  
  [...allowedFields, ...alwaysInclude].forEach(field => {
    if (record.hasOwnProperty(field)) {
      filtered[field] = record[field];
    }
  });
  
  return filtered;
}

module.exports = router;