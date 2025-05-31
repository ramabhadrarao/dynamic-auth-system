// File: models/ModelSchema.js
// Dynamic model schema definition storage

const mongoose = require('mongoose');

const fieldSchemaDefinition = {
  name: {
    type: String,
    required: true
  },
  type: {
    type: String,
    required: true,
    enum: [
      'String', 'Number', 'Date', 'Boolean', 'ObjectId', 
      'Array', 'Mixed', 'Buffer', 'Decimal128', 'Map'
    ]
  },
  required: {
    type: Boolean,
    default: false
  },
  unique: {
    type: Boolean,
    default: false
  },
  default: {
    type: mongoose.Schema.Types.Mixed
  },
  enum: [{
    type: String
  }],
  min: {
    type: mongoose.Schema.Types.Mixed
  },
  max: {
    type: mongoose.Schema.Types.Mixed
  },
  minlength: {
    type: Number
  },
  maxlength: {
    type: Number
  },
  match: {
    type: String // Regex pattern as string
  },
  ref: {
    type: String // Reference model name
  },
  trim: {
    type: Boolean,
    default: false
  },
  lowercase: {
    type: Boolean,
    default: false
  },
  uppercase: {
    type: Boolean,
    default: false
  },
  index: {
    type: Boolean,
    default: false
  },
  sparse: {
    type: Boolean,
    default: false
  },
  // UI-specific properties
  label: {
    type: String
  },
  placeholder: {
    type: String
  },
  helpText: {
    type: String
  },
  inputType: {
    type: String,
    enum: [
      'text', 'email', 'password', 'number', 'tel', 'url',
      'textarea', 'select', 'checkbox', 'radio', 'date',
      'datetime-local', 'time', 'file', 'hidden'
    ],
    default: 'text'
  },
  options: [{
    label: String,
    value: String
  }],
  validationRules: [{
    rule: String,
    message: String
  }],
  displayOrder: {
    type: Number,
    default: 0
  },
  showInList: {
    type: Boolean,
    default: true
  },
  showInForm: {
    type: Boolean,
    default: true
  },
  showInDetail: {
    type: Boolean,
    default: true
  },
  searchable: {
    type: Boolean,
    default: false
  },
  sortable: {
    type: Boolean,
    default: false
  },
  filterable: {
    type: Boolean,
    default: false
  }
};

const modelSchemaSchema = new mongoose.Schema({
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
  fields: [fieldSchemaDefinition],
  options: {
    timestamps: {
      type: Boolean,
      default: true
    },
    collection: {
      type: String
    },
    toJSON: {
      virtuals: {
        type: Boolean,
        default: true
      }
    },
    toObject: {
      virtuals: {
        type: Boolean,
        default: true
      }
    }
  },
  indexes: [{
    fields: {
      type: mongoose.Schema.Types.Mixed,
      required: true
    },
    options: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  }],
  virtuals: [{
    name: {
      type: String,
      required: true
    },
    get: {
      type: String // Function as string
    },
    set: {
      type: String // Function as string
    }
  }],
  methods: [{
    name: {
      type: String,
      required: true
    },
    function: {
      type: String // Function as string
    }
  }],
  statics: [{
    name: {
      type: String,
      required: true
    },
    function: {
      type: String // Function as string
    }
  }],
  middleware: [{
    type: {
      type: String,
      enum: ['pre', 'post'],
      required: true
    },
    hook: {
      type: String,
      required: true
    },
    function: {
      type: String // Function as string
    }
  }],
  permissions: {
    create: [{
      role: String,
      conditions: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
      }
    }],
    read: [{
      role: String,
      conditions: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
      }
    }],
    update: [{
      role: String,
      conditions: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
      }
    }],
    delete: [{
      role: String,
      conditions: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
      }
    }]
  },
  ui: {
    icon: {
      type: String,
      default: 'ti-file'
    },
    color: {
      type: String,
      default: 'primary'
    },
    listView: {
      fieldsPerRow: {
        type: Number,
        default: 1
      },
      sortBy: {
        type: String
      },
      sortOrder: {
        type: String,
        enum: ['asc', 'desc'],
        default: 'desc'
      },
      pageSize: {
        type: Number,
        default: 10
      }
    },
    formView: {
      fieldsPerRow: {
        type: Number,
        default: 1
      },
      showTabs: {
        type: Boolean,
        default: false
      },
      tabs: [{
        name: String,
        fields: [String]
      }]
    }
  },
  status: {
    type: String,
    enum: ['draft', 'active', 'deprecated'],
    default: 'draft'
  },
  version: {
    type: String,
    default: '1.0.0'
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
modelSchemaSchema.index({ name: 1 });
modelSchemaSchema.index({ status: 1 });
modelSchemaSchema.index({ createdBy: 1 });

// Pre-save middleware
modelSchemaSchema.pre('save', function(next) {
  // Set collection name if not provided
  if (!this.options.collection) {
    this.options.collection = this.name.toLowerCase() + 's';
  }
  
  // Set display order for fields if not set
  this.fields.forEach((field, index) => {
    if (field.displayOrder === undefined || field.displayOrder === 0) {
      field.displayOrder = (index + 1) * 10;
    }
  });
  
  next();
});

// Method to generate Mongoose schema
modelSchemaSchema.methods.toMongooseSchema = function() {
  const schemaDefinition = {};
  
  this.fields.forEach(field => {
    const fieldDef = {
      type: mongoose.Schema.Types[field.type] || String
    };
    
    // Add field properties
    if (field.required) fieldDef.required = field.required;
    if (field.unique) fieldDef.unique = field.unique;
    if (field.default !== undefined) fieldDef.default = field.default;
    if (field.enum && field.enum.length > 0) fieldDef.enum = field.enum;
    if (field.min !== undefined) fieldDef.min = field.min;
    if (field.max !== undefined) fieldDef.max = field.max;
    if (field.minlength) fieldDef.minlength = field.minlength;
    if (field.maxlength) fieldDef.maxlength = field.maxlength;
    if (field.match) fieldDef.match = new RegExp(field.match);
    if (field.ref) fieldDef.ref = field.ref;
    if (field.trim) fieldDef.trim = field.trim;
    if (field.lowercase) fieldDef.lowercase = field.lowercase;
    if (field.uppercase) fieldDef.uppercase = field.uppercase;
    if (field.index) fieldDef.index = field.index;
    if (field.sparse) fieldDef.sparse = field.sparse;
    
    schemaDefinition[field.name] = fieldDef;
  });
  
  return new mongoose.Schema(schemaDefinition, this.options);
};

// Method to validate field configuration
modelSchemaSchema.methods.validateFields = function() {
  const errors = [];
  
  this.fields.forEach((field, index) => {
    if (!field.name) {
      errors.push(`Field at index ${index} is missing a name`);
    }
    
    if (!field.type) {
      errors.push(`Field '${field.name}' is missing a type`);
    }
    
    if (field.ref && field.type !== 'ObjectId') {
      errors.push(`Field '${field.name}' has a reference but type is not ObjectId`);
    }
  });
  
  return errors;
};

module.exports = mongoose.model('ModelSchema', modelSchemaSchema);