// File: services/dynamicModelService.js
// Service for dynamic model creation and management

const mongoose = require('mongoose');
const ModelSchema = require('../models/ModelSchema');
const fs = require('fs').promises;
const path = require('path');

class DynamicModelService {
  constructor() {
    this.loadedModels = new Map();
    this.modelGenerators = new Map();
  }

  // Load existing models from database on startup
  async loadExistingModels() {
    try {
      const modelSchemas = await ModelSchema.find({ status: 'active' });
      
      for (const schemaDoc of modelSchemas) {
        await this.createModel(schemaDoc);
      }
      
      console.log(`Loaded ${modelSchemas.length} dynamic models`);
      return modelSchemas.length;
    } catch (error) {
      console.error('Error loading existing models:', error);
      throw error;
    }
  }

  // Create a new dynamic model
  async createModel(schemaDoc) {
    try {
      const modelName = schemaDoc.name;
      
      // Check if model already exists
      if (mongoose.models[modelName]) {
        console.log(`Model ${modelName} already exists, skipping creation`);
        return mongoose.models[modelName];
      }

      // Generate Mongoose schema
      const mongooseSchema = this.generateMongooseSchema(schemaDoc);
      
      // Add custom methods, statics, and virtuals
      this.addCustomMethods(mongooseSchema, schemaDoc);
      this.addCustomStatics(mongooseSchema, schemaDoc);
      this.addCustomVirtuals(mongooseSchema, schemaDoc);
      this.addMiddleware(mongooseSchema, schemaDoc);
      
      // Create the model
      const Model = mongoose.model(modelName, mongooseSchema, schemaDoc.options.collection);
      
      // Store reference
      this.loadedModels.set(modelName, {
        model: Model,
        schema: schemaDoc,
        createdAt: new Date()
      });

      // Generate controller and routes if needed
      await this.generateController(schemaDoc);
      await this.generateViews(schemaDoc);
      
      console.log(`Created dynamic model: ${modelName}`);
      return Model;
    } catch (error) {
      console.error(`Error creating model ${schemaDoc.name}:`, error);
      throw error;
    }
  }

  // Generate Mongoose schema from schema document
  generateMongooseSchema(schemaDoc) {
    const schemaDefinition = {};
    
    // Process each field
    schemaDoc.fields.forEach(fieldDef => {
      const fieldConfig = this.processFieldDefinition(fieldDef);
      schemaDefinition[fieldDef.name] = fieldConfig;
    });

    // Create schema with options
    const schema = new mongoose.Schema(schemaDefinition, {
      timestamps: schemaDoc.options.timestamps !== false,
      collection: schemaDoc.options.collection,
      toJSON: { virtuals: true },
      toObject: { virtuals: true },
      ...schemaDoc.options
    });

    // Add indexes
    if (schemaDoc.indexes && schemaDoc.indexes.length > 0) {
      schemaDoc.indexes.forEach(indexDef => {
        schema.index(indexDef.fields, indexDef.options || {});
      });
    }

    return schema;
  }

  // Process individual field definition
  processFieldDefinition(fieldDef) {
    const fieldConfig = {};
    
    // Determine Mongoose type
    fieldConfig.type = this.getMongooseType(fieldDef.type);
    
    // Add field properties
    if (fieldDef.required) fieldConfig.required = fieldDef.required;
    if (fieldDef.unique) fieldConfig.unique = fieldDef.unique;
    if (fieldDef.default !== undefined) fieldConfig.default = fieldDef.default;
    if (fieldDef.enum && fieldDef.enum.length > 0) fieldConfig.enum = fieldDef.enum;
    if (fieldDef.min !== undefined) fieldConfig.min = fieldDef.min;
    if (fieldDef.max !== undefined) fieldConfig.max = fieldDef.max;
    if (fieldDef.minlength) fieldConfig.minlength = fieldDef.minlength;
    if (fieldDef.maxlength) fieldConfig.maxlength = fieldDef.maxlength;
    if (fieldDef.match) fieldConfig.match = new RegExp(fieldDef.match);
    if (fieldDef.ref) fieldConfig.ref = fieldDef.ref;
    if (fieldDef.trim) fieldConfig.trim = fieldDef.trim;
    if (fieldDef.lowercase) fieldConfig.lowercase = fieldDef.lowercase;
    if (fieldDef.uppercase) fieldConfig.uppercase = fieldDef.uppercase;
    if (fieldDef.index) fieldConfig.index = fieldDef.index;
    if (fieldDef.sparse) fieldConfig.sparse = fieldDef.sparse;

    return fieldConfig;
  }

  // Get Mongoose type from string
  getMongooseType(typeString) {
    switch (typeString) {
      case 'String':
        return String;
      case 'Number':
        return Number;
      case 'Date':
        return Date;
      case 'Boolean':
        return Boolean;
      case 'ObjectId':
        return mongoose.Schema.Types.ObjectId;
      case 'Array':
        return Array;
      case 'Mixed':
        return mongoose.Schema.Types.Mixed;
      case 'Buffer':
        return Buffer;
      case 'Decimal128':
        return mongoose.Schema.Types.Decimal128;
      case 'Map':
        return Map;
      default:
        return String;
    }
  }

  // Add custom methods to schema
  addCustomMethods(schema, schemaDoc) {
    if (schemaDoc.methods && schemaDoc.methods.length > 0) {
      schemaDoc.methods.forEach(methodDef => {
        try {
          // Convert string function to actual function
          const methodFunction = new Function('return ' + methodDef.function)();
          schema.methods[methodDef.name] = methodFunction;
        } catch (error) {
          console.error(`Error adding method ${methodDef.name}:`, error);
        }
      });
    }
  }

  // Add custom statics to schema
  addCustomStatics(schema, schemaDoc) {
    if (schemaDoc.statics && schemaDoc.statics.length > 0) {
      schemaDoc.statics.forEach(staticDef => {
        try {
          // Convert string function to actual function
          const staticFunction = new Function('return ' + staticDef.function)();
          schema.statics[staticDef.name] = staticFunction;
        } catch (error) {
          console.error(`Error adding static ${staticDef.name}:`, error);
        }
      });
    }
  }

  // Add custom virtuals to schema
  addCustomVirtuals(schema, schemaDoc) {
    if (schemaDoc.virtuals && schemaDoc.virtuals.length > 0) {
      schemaDoc.virtuals.forEach(virtualDef => {
        try {
          const virtual = schema.virtual(virtualDef.name);
          
          if (virtualDef.get) {
            const getFunction = new Function('return ' + virtualDef.get)();
            virtual.get(getFunction);
          }
          
          if (virtualDef.set) {
            const setFunction = new Function('return ' + virtualDef.set)();
            virtual.set(setFunction);
          }
        } catch (error) {
          console.error(`Error adding virtual ${virtualDef.name}:`, error);
        }
      });
    }
  }

  // Add middleware to schema
  addMiddleware(schema, schemaDoc) {
    if (schemaDoc.middleware && schemaDoc.middleware.length > 0) {
      schemaDoc.middleware.forEach(middlewareDef => {
        try {
          const middlewareFunction = new Function('return ' + middlewareDef.function)();
          
          if (middlewareDef.type === 'pre') {
            schema.pre(middlewareDef.hook, middlewareFunction);
          } else if (middlewareDef.type === 'post') {
            schema.post(middlewareDef.hook, middlewareFunction);
          }
        } catch (error) {
          console.error(`Error adding middleware ${middlewareDef.hook}:`, error);
        }
      });
    }
  }

  // Generate controller file for the model
  async generateController(schemaDoc) {
    try {
      const controllerTemplate = this.getControllerTemplate(schemaDoc);
      const controllerPath = path.join(__dirname, '../controllers', `${schemaDoc.name}Controller.js`);
      
      // Ensure controllers directory exists
      await fs.mkdir(path.dirname(controllerPath), { recursive: true });
      
      await fs.writeFile(controllerPath, controllerTemplate);
      console.log(`Generated controller: ${controllerPath}`);
    } catch (error) {
      console.error(`Error generating controller for ${schemaDoc.name}:`, error);
    }
  }

  // Generate Pug views for the model
  async generateViews(schemaDoc) {
    try {
      const viewsDir = path.join(__dirname, '../views', schemaDoc.name.toLowerCase());
      await fs.mkdir(viewsDir, { recursive: true });

      // Generate list view
      const listTemplate = this.getListViewTemplate(schemaDoc);
      await fs.writeFile(path.join(viewsDir, 'list.pug'), listTemplate);

      // Generate form view
      const formTemplate = this.getFormViewTemplate(schemaDoc);
      await fs.writeFile(path.join(viewsDir, 'form.pug'), formTemplate);

      // Generate detail view
      const detailTemplate = this.getDetailViewTemplate(schemaDoc);
      await fs.writeFile(path.join(viewsDir, 'detail.pug'), detailTemplate);

      console.log(`Generated views for: ${schemaDoc.name}`);
    } catch (error) {
      console.error(`Error generating views for ${schemaDoc.name}:`, error);
    }
  }

  // Get controller template
  getControllerTemplate(schemaDoc) {
    return `// File: controllers/${schemaDoc.name}Controller.js
// Auto-generated controller for ${schemaDoc.displayName}

const ${schemaDoc.name} = require('mongoose').model('${schemaDoc.name}');
const { asyncHandler } = require('../middleware/errorHandler');

// Get all ${schemaDoc.name.toLowerCase()} records
exports.getAll = asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;
  
  const filter = req.dataFilter || {};
  const query = ${schemaDoc.name}.find(filter);
  
  // Apply search if provided
  if (req.query.search) {
    const searchFields = ${JSON.stringify(schemaDoc.fields.filter(f => f.searchable).map(f => f.name))};
    const searchConditions = searchFields.map(field => ({
      [field]: { $regex: req.query.search, $options: 'i' }
    }));
    if (searchConditions.length > 0) {
      query.or(searchConditions);
    }
  }
  
  const total = await ${schemaDoc.name}.countDocuments(query.getFilter());
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

// Get single ${schemaDoc.name.toLowerCase()} record
exports.getById = asyncHandler(async (req, res) => {
  const record = await ${schemaDoc.name}.findById(req.params.id);
  
  if (!record) {
    return res.status(404).json({ error: '${schemaDoc.displayName} not found' });
  }
  
  res.json({ record });
});

// Create new ${schemaDoc.name.toLowerCase()} record
exports.create = asyncHandler(async (req, res) => {
  const record = new ${schemaDoc.name}(req.body);
  
  // Set ownership if field exists
  if (record.schema.paths.owner) {
    record.owner = req.user._id;
  }
  
  await record.save();
  
  res.status(201).json({
    message: '${schemaDoc.displayName} created successfully',
    record
  });
});

// Update ${schemaDoc.name.toLowerCase()} record
exports.update = asyncHandler(async (req, res) => {
  const record = await ${schemaDoc.name}.findById(req.params.id);
  
  if (!record) {
    return res.status(404).json({ error: '${schemaDoc.displayName} not found' });
  }
  
  Object.assign(record, req.body);
  await record.save();
  
  res.json({
    message: '${schemaDoc.displayName} updated successfully',
    record
  });
});

// Delete ${schemaDoc.name.toLowerCase()} record
exports.delete = asyncHandler(async (req, res) => {
  const record = await ${schemaDoc.name}.findById(req.params.id);
  
  if (!record) {
    return res.status(404).json({ error: '${schemaDoc.displayName} not found' });
  }
  
  await record.deleteOne();
  
  res.json({
    message: '${schemaDoc.displayName} deleted successfully'
  });
});
`;
  }

  // Get list view template
  getListViewTemplate(schemaDoc) {
    const listFields = schemaDoc.fields.filter(f => f.showInList).sort((a, b) => a.displayOrder - b.displayOrder);
    
    return `//- File: views/${schemaDoc.name.toLowerCase()}/list.pug
//- Auto-generated list view for ${schemaDoc.displayName}

extends ../layout

block content
  .container-fluid
    .row
      .col-12
        .card
          .card-header.d-flex.justify-content-between.align-items-center
            h3.card-title
              i.${schemaDoc.ui.icon || 'ti-file'}.me-2
              | ${schemaDoc.displayName}
            .btn-group
              a.btn.btn-primary(href='/admin/${schemaDoc.name.toLowerCase()}/new')
                i.ti-plus.me-1
                | Add New
              
          .card-body
            //- Search and filters
            .row.mb-3
              .col-md-6
                .input-group
                  input.form-control(type='text', placeholder='Search...', name='search')
                  button.btn.btn-outline-secondary(type='button')
                    i.ti-search
                    
            //- Data table
            .table-responsive
              table.table.table-striped
                thead
                  tr
${listFields.map(field => `                    th ${field.label || field.name}`).join('\n')}
                    th Actions
                tbody
                  each record in records
                    tr
${listFields.map(field => `                      td= record.${field.name}`).join('\n')}
                      td
                        .btn-group
                          a.btn.btn-sm.btn-outline-primary(href='/admin/${schemaDoc.name.toLowerCase()}/' + record._id)
                            i.ti-eye
                          a.btn.btn-sm.btn-outline-secondary(href='/admin/${schemaDoc.name.toLowerCase()}/' + record._id + '/edit')
                            i.ti-edit
                          button.btn.btn-sm.btn-outline-danger(onclick='deleteRecord("' + record._id + '")')
                            i.ti-trash
                            
            //- Pagination
            if pagination && pagination.pages > 1
              nav
                ul.pagination.justify-content-center
                  li.page-item(class=pagination.page <= 1 ? 'disabled' : '')
                    a.page-link(href='?page=' + (pagination.page - 1)) Previous
                  - for (let i = 1; i <= pagination.pages; i++)
                    li.page-item(class=pagination.page === i ? 'active' : '')
                      a.page-link(href='?page=' + i)= i
                  li.page-item(class=pagination.page >= pagination.pages ? 'disabled' : '')
                    a.page-link(href='?page=' + (pagination.page + 1)) Next

block scripts
  script.
    function deleteRecord(id) {
      if (confirm('Are you sure you want to delete this record?')) {
        fetch('/api/dynamic/${schemaDoc.name}/' + id, {
          method: 'DELETE',
          headers: {
            'Authorization': 'Bearer ' + localStorage.getItem('token')
          }
        })
        .then(response => response.json())
        .then(data => {
          if (data.error) {
            alert('Error: ' + data.error);
          } else {
            location.reload();
          }
        })
        .catch(error => {
          alert('Error: ' + error.message);
        });
      }
    }
`;
  }

  // Get form view template
  getFormViewTemplate(schemaDoc) {
    const formFields = schemaDoc.fields.filter(f => f.showInForm).sort((a, b) => a.displayOrder - b.displayOrder);
    
    return `//- File: views/${schemaDoc.name.toLowerCase()}/form.pug
//- Auto-generated form view for ${schemaDoc.displayName}

extends ../layout

block content
  .container-fluid
    .row
      .col-12
        .card
          .card-header
            h3.card-title
              i.${schemaDoc.ui.icon || 'ti-file'}.me-2
              | #{isEdit ? 'Edit' : 'Create'} ${schemaDoc.displayName}
              
          .card-body
            form#recordForm
${formFields.map(field => this.generateFormField(field)).join('\n')}
              
              .row.mt-3
                .col-12
                  button.btn.btn-primary(type='submit')
                    i.ti-check.me-1
                    | #{isEdit ? 'Update' : 'Create'}
                  a.btn.btn-secondary.ms-2(href='/admin/${schemaDoc.name.toLowerCase()}')
                    i.ti-arrow-left.me-1
                    | Back to List

block scripts
  script.
    document.getElementById('recordForm').addEventListener('submit', function(e) {
      e.preventDefault();
      
      const formData = new FormData(this);
      const data = Object.fromEntries(formData.entries());
      
      const method = isEdit ? 'PUT' : 'POST';
      const url = isEdit ? '/api/dynamic/${schemaDoc.name}/' + recordId : '/api/dynamic/${schemaDoc.name}';
      
      fetch(url, {
        method: method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + localStorage.getItem('token')
        },
        body: JSON.stringify(data)
      })
      .then(response => response.json())
      .then(data => {
        if (data.error) {
          alert('Error: ' + data.error);
        } else {
          window.location.href = '/admin/${schemaDoc.name.toLowerCase()}';
        }
      })
      .catch(error => {
        alert('Error: ' + error.message);
      });
    });
`;
  }

  // Generate form field HTML
  generateFormField(field) {
    const fieldId = field.name;
    const fieldLabel = field.label || field.name;
    const required = field.required ? 'required' : '';
    const placeholder = field.placeholder || '';
    
    let fieldHtml = `              .row.mb-3
                .col-md-6
                  label.form-label(for='${fieldId}') ${fieldLabel}${field.required ? ' *' : ''}`;
    
    switch (field.inputType) {
      case 'textarea':
        fieldHtml += `
                  textarea.form-control(id='${fieldId}', name='${fieldId}', placeholder='${placeholder}', ${required})`;
        break;
      case 'select':
        fieldHtml += `
                  select.form-control(id='${fieldId}', name='${fieldId}', ${required})`;
        if (field.options) {
          field.options.forEach(option => {
            fieldHtml += `
                    option(value='${option.value}') ${option.label}`;
          });
        }
        break;
      case 'checkbox':
        fieldHtml += `
                  .form-check
                    input.form-check-input(type='checkbox', id='${fieldId}', name='${fieldId}')
                    label.form-check-label(for='${fieldId}') ${fieldLabel}`;
        break;
      default:
        fieldHtml += `
                  input.form-control(type='${field.inputType || 'text'}', id='${fieldId}', name='${fieldId}', placeholder='${placeholder}', ${required})`;
    }
    
    if (field.helpText) {
      fieldHtml += `
                  small.form-text.text-muted ${field.helpText}`;
    }
    
    return fieldHtml;
  }

  // Get detail view template
  getDetailViewTemplate(schemaDoc) {
    const detailFields = schemaDoc.fields.filter(f => f.showInDetail).sort((a, b) => a.displayOrder - b.displayOrder);
    
    return `//- File: views/${schemaDoc.name.toLowerCase()}/detail.pug
//- Auto-generated detail view for ${schemaDoc.displayName}

extends ../layout

block content
  .container-fluid
    .row
      .col-12
        .card
          .card-header.d-flex.justify-content-between.align-items-center
            h3.card-title
              i.${schemaDoc.ui.icon || 'ti-file'}.me-2
              | ${schemaDoc.displayName} Details
            .btn-group
              a.btn.btn-secondary(href='/admin/${schemaDoc.name.toLowerCase()}/' + record._id + '/edit')
                i.ti-edit.me-1
                | Edit
              a.btn.btn-outline-secondary(href='/admin/${schemaDoc.name.toLowerCase()}')
                i.ti-arrow-left.me-1
                | Back to List
                
          .card-body
            .row
${detailFields.map(field => `              .col-md-6.mb-3
                strong ${field.label || field.name}:
                p= record.${field.name} || '-'`).join('\n')}
                
            if record.createdAt || record.updatedAt
              hr
              .row
                if record.createdAt
                  .col-md-6.mb-3
                    strong Created:
                    p= moment(record.createdAt).format('YYYY-MM-DD HH:mm:ss')
                if record.updatedAt
                  .col-md-6.mb-3
                    strong Updated:
                    p= moment(record.updatedAt).format('YYYY-MM-DD HH:mm:ss')
`;
  }

  // Update existing model
  async updateModel(schemaDoc) {
    try {
      const modelName = schemaDoc.name;
      
      // Remove existing model
      if (mongoose.models[modelName]) {
        delete mongoose.models[modelName];
        delete mongoose.modelSchemas[modelName];
      }
      
      // Recreate model
      await this.createModel(schemaDoc);
      
      console.log(`Updated dynamic model: ${modelName}`);
    } catch (error) {
      console.error(`Error updating model ${schemaDoc.name}:`, error);
      throw error;
    }
  }

  // Delete model
  async deleteModel(modelName) {
    try {
      // Remove from Mongoose
      if (mongoose.models[modelName]) {
        delete mongoose.models[modelName];
        delete mongoose.modelSchemas[modelName];
      }
      
      // Remove from loaded models
      this.loadedModels.delete(modelName);
      
      // TODO: Remove generated files
      
      console.log(`Deleted dynamic model: ${modelName}`);
    } catch (error) {
      console.error(`Error deleting model ${modelName}:`, error);
      throw error;
    }
  }

  // Get all loaded models
  getLoadedModels() {
    return Array.from(this.loadedModels.keys());
  }

  // Get model info
  getModelInfo(modelName) {
    return this.loadedModels.get(modelName);
  }
}

// Export singleton instance
module.exports = new DynamicModelService();