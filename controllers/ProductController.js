// File: controllers/ProductController.js
// Auto-generated controller for Products

const Product = require('mongoose').model('Product');
const { asyncHandler } = require('../middleware/errorHandler');

// Get all product records
exports.getAll = asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;
  
  const filter = req.dataFilter || {};
  const query = Product.find(filter);
  
  // Apply search if provided
  if (req.query.search) {
    const searchFields = ["name","description","sku"];
    const searchConditions = searchFields.map(field => ({
      [field]: { $regex: req.query.search, $options: 'i' }
    }));
    if (searchConditions.length > 0) {
      query.or(searchConditions);
    }
  }
  
  const total = await Product.countDocuments(query.getFilter());
  const records = await query.skip(skip).limit(limit).exec();
  
  res.json({
    records,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }
  });
});

// Get single product record
exports.getById = asyncHandler(async (req, res) => {
  const record = await Product.findById(req.params.id);
  
  if (!record) {
    return res.status(404).json({ error: 'Products not found' });
  }
  
  res.json({ record });
});

// Create new product record
exports.create = asyncHandler(async (req, res) => {
  const record = new Product(req.body);
  
  // Set ownership if field exists
  if (record.schema.paths.owner) {
    record.owner = req.user._id;
  }
  
  await record.save();
  
  res.status(201).json({
    message: 'Products created successfully',
    record
  });
});

// Update product record
exports.update = asyncHandler(async (req, res) => {
  const record = await Product.findById(req.params.id);
  
  if (!record) {
    return res.status(404).json({ error: 'Products not found' });
  }
  
  Object.assign(record, req.body);
  await record.save();
  
  res.json({
    message: 'Products updated successfully',
    record
  });
});

// Delete product record
exports.delete = asyncHandler(async (req, res) => {
  const record = await Product.findById(req.params.id);
  
  if (!record) {
    return res.status(404).json({ error: 'Products not found' });
  }
  
  await record.deleteOne();
  
  res.json({
    message: 'Products deleted successfully'
  });
});
