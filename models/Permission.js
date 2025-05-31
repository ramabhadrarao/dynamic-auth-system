// File: models/Permission.js
// Permission and policy model for RBAC/ABAC

const mongoose = require('mongoose');

const permissionSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  displayName: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  resource: {
    type: String,
    required: true,
    trim: true
  },
  action: {
    type: String,
    required: true,
    enum: ['create', 'read', 'update', 'delete', 'execute', 'manage'],
    trim: true
  },
  effect: {
    type: String,
    enum: ['allow', 'deny'],
    default: 'allow'
  },
  conditions: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  attributes: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  priority: {
    type: Number,
    default: 0
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

const roleSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  displayName: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  permissions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Permission'
  }],
  inheritFrom: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role'
  }],
  level: {
    type: Number,
    default: 0
  },
  isSystemRole: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

const policySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  displayName: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  type: {
    type: String,
    enum: ['rbac', 'abac', 'hybrid'],
    default: 'rbac'
  },
  rules: [{
    subject: {
      type: String, // Role or user attribute
      required: true
    },
    resource: {
      type: String,
      required: true
    },
    action: {
      type: String,
      required: true
    },
    effect: {
      type: String,
      enum: ['allow', 'deny'],
      default: 'allow'
    },
    conditions: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  }],
  priority: {
    type: Number,
    default: 0
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Indexes
permissionSchema.index({ resource: 1, action: 1 });
permissionSchema.index({ isActive: 1 });
permissionSchema.index({ priority: -1 });

roleSchema.index({ name: 1 });
roleSchema.index({ level: 1 });
roleSchema.index({ isActive: 1 });

policySchema.index({ type: 1 });
policySchema.index({ isActive: 1 });
policySchema.index({ priority: -1 });

// Permission Methods
permissionSchema.methods.evaluateConditions = function(context) {
  if (!this.conditions || Object.keys(this.conditions).length === 0) {
    return true;
  }
  
  // Simple condition evaluation (can be extended)
  for (const [key, value] of Object.entries(this.conditions)) {
    if (key === 'owner' && value === '${user.id}') {
      return context.resource && context.resource.owner && 
             context.resource.owner.toString() === context.user._id.toString();
    }
    
    if (key === 'department' && value === '${user.department}') {
      return context.resource && context.resource.department === context.user.department;
    }
    
    if (key === 'time_range') {
      const now = new Date();
      const startTime = new Date(value.start);
      const endTime = new Date(value.end);
      return now >= startTime && now <= endTime;
    }
    
    // Add more condition types as needed
  }
  
  return true;
};

// Role Methods
roleSchema.methods.getAllPermissions = async function() {
  const allPermissions = new Set();
  
  // Add direct permissions
  for (const permissionId of this.permissions) {
    allPermissions.add(permissionId.toString());
  }
  
  // Add inherited permissions
  if (this.inheritFrom && this.inheritFrom.length > 0) {
    const Role = mongoose.model('Role');
    for (const parentRoleId of this.inheritFrom) {
      const parentRole = await Role.findById(parentRoleId).populate('permissions');
      if (parentRole) {
        const parentPermissions = await parentRole.getAllPermissions();
        parentPermissions.forEach(p => allPermissions.add(p));
      }
    }
  }
  
  return Array.from(allPermissions);
};

// Policy Methods
policySchema.methods.evaluate = function(subject, resource, action, context = {}) {
  let result = { effect: 'deny', reason: 'No matching rule' };
  
  // Sort rules by priority (higher priority first)
  const sortedRules = this.rules.sort((a, b) => (b.priority || 0) - (a.priority || 0));
  
  for (const rule of sortedRules) {
    if (this.matchesRule(rule, subject, resource, action, context)) {
      result = {
        effect: rule.effect,
        reason: `Matched rule: ${rule.subject} ${rule.action} ${rule.resource}`,
        rule: rule
      };
      
      // If deny effect, return immediately
      if (rule.effect === 'deny') {
        break;
      }
    }
  }
  
  return result;
};

policySchema.methods.matchesRule = function(rule, subject, resource, action, context) {
  // Check action match
  if (rule.action !== action && rule.action !== '*') {
    return false;
  }
  
  // Check resource match
  if (rule.resource !== resource && rule.resource !== '*') {
    return false;
  }
  
  // Check subject match (role or attribute)
  if (!this.matchesSubject(rule.subject, subject, context)) {
    return false;
  }
  
  // Check conditions
  if (rule.conditions && Object.keys(rule.conditions).length > 0) {
    return this.evaluateConditions(rule.conditions, context);
  }
  
  return true;
};

policySchema.methods.matchesSubject = function(ruleSubject, subject, context) {
  // Direct role match
  if (subject.role === ruleSubject) {
    return true;
  }
  
  // Attribute match (ABAC)
  if (ruleSubject.startsWith('${') && ruleSubject.endsWith('}')) {
    const attributePath = ruleSubject.slice(2, -1);
    const attributeValue = this.getNestedProperty(subject, attributePath);
    return !!attributeValue;
  }
  
  return false;
};

policySchema.methods.evaluateConditions = function(conditions, context) {
  for (const [key, value] of Object.entries(conditions)) {
    if (!this.evaluateCondition(key, value, context)) {
      return false;
    }
  }
  return true;
};

policySchema.methods.evaluateCondition = function(key, value, context) {
  switch (key) {
    case 'owner':
      return context.resource && context.resource.owner && 
             context.resource.owner.toString() === context.user._id.toString();
    
    case 'department':
      return context.resource && context.resource.department === context.user.department;
    
    case 'time_range':
      const now = new Date();
      const startTime = new Date(value.start);
      const endTime = new Date(value.end);
      return now >= startTime && now <= endTime;
    
    case 'ip_address':
      return context.clientIp && this.matchesIpPattern(context.clientIp, value);
    
    default:
      return true;
  }
};

policySchema.methods.getNestedProperty = function(obj, path) {
  return path.split('.').reduce((current, key) => current && current[key], obj);
};

policySchema.methods.matchesIpPattern = function(ip, pattern) {
  // Simple IP pattern matching (can be extended)
  if (pattern === '*') return true;
  if (pattern.includes('/')) {
    // CIDR notation support would go here
    return false;
  }
  return ip === pattern;
};

// Export models
const Permission = mongoose.model('Permission', permissionSchema);
const Role = mongoose.model('Role', roleSchema);
const Policy = mongoose.model('Policy', policySchema);

module.exports = {
  Permission,
  Role,
  Policy
};