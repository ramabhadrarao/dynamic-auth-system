// File: routes/files.js
// File upload and management routes

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const { body, validationResult } = require('express-validator');
const Attachment = require('../models/Attachment');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = process.env.UPLOAD_PATH || './uploads';
    try {
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (error) {
      cb(error);
    }
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024, // 10MB default
    files: 10 // Max 10 files at once
  },
  fileFilter: (req, file, cb) => {
    // Add file type validation here if needed
    cb(null, true);
  }
});

// Upload single file
router.post('/upload', upload.single('file'), asyncHandler(async (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      success: false,
      error: 'No file uploaded'
    });
  }

  const attachment = new Attachment({
    filename: req.file.filename,
    originalName: req.file.originalname,
    mimetype: req.file.mimetype,
    size: req.file.size,
    path: req.file.path,
    uploadedBy: req.user._id,
    associatedModel: req.body.associatedModel,
    associatedId: req.body.associatedId,
    fieldName: req.body.fieldName,
    isPublic: req.body.isPublic === 'true',
    metadata: {
      tags: req.body.tags ? req.body.tags.split(',') : [],
      description: req.body.description,
      alt: req.body.alt,
      title: req.body.title
    }
  });

  await attachment.save();

  res.json({
    success: true,
    message: 'File uploaded successfully',
    file: {
      id: attachment._id,
      filename: attachment.filename,
      originalName: attachment.originalName,
      size: attachment.size,
      mimetype: attachment.mimetype,
      url: attachment.publicUrl,
      formattedSize: attachment.formattedSize
    }
  });
}));

// Upload multiple files
router.post('/upload-multiple', upload.array('files', 10), asyncHandler(async (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'No files uploaded'
    });
  }

  const attachments = [];

  for (const file of req.files) {
    const attachment = new Attachment({
      filename: file.filename,
      originalName: file.originalname,
      mimetype: file.mimetype,
      size: file.size,
      path: file.path,
      uploadedBy: req.user._id,
      associatedModel: req.body.associatedModel,
      associatedId: req.body.associatedId,
      isPublic: req.body.isPublic === 'true'
    });

    await attachment.save();
    attachments.push({
      id: attachment._id,
      filename: attachment.filename,
      originalName: attachment.originalName,
      size: attachment.size,
      mimetype: attachment.mimetype,
      url: attachment.publicUrl,
      formattedSize: attachment.formattedSize
    });
  }

  res.json({
    success: true,
    message: `${attachments.length} files uploaded successfully`,
    files: attachments
  });
}));

// Get all files
router.get('/', asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const skip = (page - 1) * limit;

  const filter = {};
  
  // Apply filters
  if (req.query.category) {
    filter.category = req.query.category;
  }
  
  if (req.query.mimetype) {
    filter.mimetype = { $regex: req.query.mimetype, $options: 'i' };
  }
  
  if (req.query.search) {
    filter.$or = [
      { originalName: { $regex: req.query.search, $options: 'i' } },
      { 'metadata.description': { $regex: req.query.search, $options: 'i' } },
      { 'metadata.tags': { $in: [new RegExp(req.query.search, 'i')] } }
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

  res.json({
    success: true,
    data: files,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }
  });
}));

// Get single file
router.get('/:id', asyncHandler(async (req, res) => {
  const file = await Attachment.findById(req.params.id)
    .populate('uploadedBy', 'username fullName');

  if (!file) {
    return res.status(404).json({
      success: false,
      error: 'File not found'
    });
  }

  // Check access permissions
  if (!file.canAccess(req.user, 'read')) {
    return res.status(403).json({
      success: false,
      error: 'Access denied'
    });
  }

  res.json({
    success: true,
    data: file
  });
}));

// Download file
router.get('/:id/download', asyncHandler(async (req, res) => {
  const file = await Attachment.findById(req.params.id);

  if (!file) {
    return res.status(404).json({
      success: false,
      error: 'File not found'
    });
  }

  // Check access permissions
  if (!file.canAccess(req.user, 'read')) {
    return res.status(403).json({
      success: false,
      error: 'Access denied'
    });
  }

  // Check if file exists on disk
  try {
    await fs.access(file.path);
  } catch (error) {
    return res.status(404).json({
      success: false,
      error: 'File not found on disk'
    });
  }

  // Increment download count
  await file.incrementDownloads();

  res.download(file.path, file.originalName);
}));

// Update file metadata
router.put('/:id', [
  body('metadata.description').optional().trim(),
  body('metadata.alt').optional().trim(),
  body('metadata.title').optional().trim(),
  body('isPublic').optional().isBoolean()
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      errors: errors.array()
    });
  }

  const file = await Attachment.findById(req.params.id);

  if (!file) {
    return res.status(404).json({
      success: false,
      error: 'File not found'
    });
  }

  // Check access permissions
  if (!file.canAccess(req.user, 'write')) {
    return res.status(403).json({
      success: false,
      error: 'Access denied'
    });
  }

  // Update allowed fields
  const allowedUpdates = ['metadata', 'isPublic'];
  Object.keys(req.body).forEach(key => {
    if (allowedUpdates.includes(key)) {
      if (key === 'metadata') {
        Object.assign(file.metadata, req.body.metadata);
      } else {
        file[key] = req.body[key];
      }
    }
  });

  await file.save();

  res.json({
    success: true,
    message: 'File updated successfully',
    data: file
  });
}));

// Delete file
router.delete('/:id', asyncHandler(async (req, res) => {
  const file = await Attachment.findById(req.params.id);

  if (!file) {
    return res.status(404).json({
      success: false,
      error: 'File not found'
    });
  }

  // Check access permissions
  if (!file.canAccess(req.user, 'delete')) {
    return res.status(403).json({
      success: false,
      error: 'Access denied'
    });
  }

  // Delete file from disk
  try {
    await fs.unlink(file.path);
  } catch (error) {
    console.error('Error deleting file from disk:', error);
  }

  // Delete from database
  await file.deleteOne();

  res.json({
    success: true,
    message: 'File deleted successfully'
  });
}));

// Get file statistics
router.get('/stats/overview', asyncHandler(async (req, res) => {
  const pipeline = [
    {
      $group: {
        _id: '$category',
        count: { $sum: 1 },
        totalSize: { $sum: '$size' }
      }
    }
  ];

  // Apply user filter for non-admin users
  if (req.user.role !== 'super_admin' && req.user.role !== 'admin') {
    pipeline.unshift({
      $match: {
        $or: [
          { uploadedBy: req.user._id },
          { isPublic: true }
        ]
      }
    });
  }

  const stats = await Attachment.aggregate(pipeline);

  const totalFiles = await Attachment.countDocuments(
    req.user.role === 'super_admin' || req.user.role === 'admin' ? {} : {
      $or: [
        { uploadedBy: req.user._id },
        { isPublic: true }
      ]
    }
  );

  const totalSize = await Attachment.aggregate([
    ...(req.user.role !== 'super_admin' && req.user.role !== 'admin' ? [{
      $match: {
        $or: [
          { uploadedBy: req.user._id },
          { isPublic: true }
        ]
      }
    }] : []),
    {
      $group: {
        _id: null,
        totalSize: { $sum: '$size' }
      }
    }
  ]);

  res.json({
    success: true,
    data: {
      totalFiles,
      totalSize: totalSize[0]?.totalSize || 0,
      byCategory: stats
    }
  });
}));

module.exports = router;