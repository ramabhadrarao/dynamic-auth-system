// File: models/Attachment.js
// File attachment model for handling uploads

const mongoose = require('mongoose');
const path = require('path');

const attachmentSchema = new mongoose.Schema({
  filename: {
    type: String,
    required: true
  },
  originalName: {
    type: String,
    required: true
  },
  mimetype: {
    type: String,
    required: true
  },
  size: {
    type: Number,
    required: true
  },
  path: {
    type: String,
    required: true
  },
  url: {
    type: String
  },
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  associatedModel: {
    type: String // Model name this file is associated with
  },
  associatedId: {
    type: mongoose.Schema.Types.ObjectId // ID of the associated document
  },
  fieldName: {
    type: String // Field name in the associated model
  },
  metadata: {
    width: Number,
    height: Number,
    duration: Number, // For video/audio files
    encoding: String,
    tags: [String],
    description: String,
    alt: String, // Alt text for images
    title: String
  },
  category: {
    type: String,
    enum: ['image', 'document', 'video', 'audio', 'archive', 'other'],
    default: 'other'
  },
  status: {
    type: String,
    enum: ['uploading', 'processed', 'failed', 'deleted'],
    default: 'processed'
  },
  isPublic: {
    type: Boolean,
    default: false
  },
  permissions: {
    read: [{
      role: String,
      users: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
    }],
    write: [{
      role: String,
      users: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
    }],
    delete: [{
      role: String,
      users: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
    }]
  },
  virus_scan: {
    scanned: {
      type: Boolean,
      default: false
    },
    clean: {
      type: Boolean,
      default: true
    },
    scanDate: Date,
    scanResult: String
  },
  versions: [{
    version: String,
    filename: String,
    size: Number,
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  downloads: {
    type: Number,
    default: 0
  },
  lastDownloaded: Date,
  expiresAt: Date // Auto-delete date
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
attachmentSchema.index({ uploadedBy: 1 });
attachmentSchema.index({ associatedModel: 1, associatedId: 1 });
attachmentSchema.index({ mimetype: 1 });
attachmentSchema.index({ category: 1 });
attachmentSchema.index({ status: 1 });
attachmentSchema.index({ createdAt: -1 });
attachmentSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Virtual for file extension
attachmentSchema.virtual('extension').get(function() {
  return path.extname(this.originalName).toLowerCase();
});

// Virtual for formatted size
attachmentSchema.virtual('formattedSize').get(function() {
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  if (this.size === 0) return '0 Bytes';
  const i = Math.floor(Math.log(this.size) / Math.log(1024));
  return Math.round(this.size / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
});

// Virtual for public URL
attachmentSchema.virtual('publicUrl').get(function() {
  if (this.url) return this.url;
  return `/uploads/${this.filename}`;
});

// Pre-save middleware
attachmentSchema.pre('save', function(next) {
  // Set category based on mimetype
  if (!this.category || this.category === 'other') {
    if (this.mimetype.startsWith('image/')) {
      this.category = 'image';
    } else if (this.mimetype.startsWith('video/')) {
      this.category = 'video';
    } else if (this.mimetype.startsWith('audio/')) {
      this.category = 'audio';
    } else if (this.mimetype.includes('pdf') || 
               this.mimetype.includes('document') || 
               this.mimetype.includes('text') ||
               this.mimetype.includes('spreadsheet') ||
               this.mimetype.includes('presentation')) {
      this.category = 'document';
    } else if (this.mimetype.includes('zip') || 
               this.mimetype.includes('rar') || 
               this.mimetype.includes('tar') ||
               this.mimetype.includes('gzip')) {
      this.category = 'archive';
    }
  }
  
  // Set URL if not provided
  if (!this.url) {
    this.url = this.publicUrl;
  }
  
  next();
});

// Method to check if user can access file
attachmentSchema.methods.canAccess = function(user, action = 'read') {
  // File owner can always access
  if (this.uploadedBy.toString() === user._id.toString()) {
    return true;
  }
  
  // Super admin can always access
  if (user.role === 'super_admin') {
    return true;
  }
  
  // Check if file is public and action is read
  if (this.isPublic && action === 'read') {
    return true;
  }
  
  // Check specific permissions
  const permission = this.permissions[action];
  if (!permission) return false;
  
  for (const perm of permission) {
    // Check role-based permission
    if (perm.role && user.role === perm.role) {
      return true;
    }
    
    // Check user-specific permission
    if (perm.users && perm.users.some(userId => userId.toString() === user._id.toString())) {
      return true;
    }
  }
  
  return false;
};

// Method to increment download count
attachmentSchema.methods.incrementDownloads = function() {
  this.downloads += 1;
  this.lastDownloaded = new Date();
  return this.save();
};

// Static method to find by user
attachmentSchema.statics.findByUser = function(userId, options = {}) {
  const query = { uploadedBy: userId };
  
  if (options.category) {
    query.category = options.category;
  }
  
  if (options.associatedModel) {
    query.associatedModel = options.associatedModel;
  }
  
  return this.find(query);
};

// Static method to find by association
attachmentSchema.statics.findByAssociation = function(modelName, documentId) {
  return this.find({
    associatedModel: modelName,
    associatedId: documentId
  });
};

// Static method to cleanup expired files
attachmentSchema.statics.cleanupExpired = function() {
  return this.deleteMany({
    expiresAt: { $lte: new Date() }
  });
};

module.exports = mongoose.model('Attachment', attachmentSchema);