// semantic/extractor.js - Unified extraction entry point
const path = require('path');
const fs = require('fs');
const { JavaScriptAdapter } = require('./adapters/javascript');
const { PythonAdapter } = require('./adapters/python');
const { validateGraph } = require('./schema');

class SemanticExtractor {
  constructor() {
    this.adapters = { javascript: new JavaScriptAdapter(), python: new PythonAdapter() };
  }

  extract(projectPath, options = {}) {
    if (!fs.existsSync(projectPath)) throw new Error(`Path not found: ${projectPath}`);
    const language = options.language || this._detectLanguage(projectPath);
    const adapter = this.adapters[language];
    if (!adapter) throw new Error(`Unsupported language: ${language}. Supported: ${Object.keys(this.adapters).join(', ')}`);
    const graph = adapter.extract(projectPath, { name: options.name, threatModel: options.threatModel });
    const validation = validateGraph(graph);
    if (!validation.valid) console.warn(`Graph validation warnings: ${validation.errors.map(e => typeof e === 'string' ? e : e.message).join('; ')}`);
    return graph;
  }

  extractBatch(projects) {
    const results = new Map();
    for (const proj of projects) {
      try {
        const graph = this.extract(proj.path, { name: proj.name });
        results.set(proj.name || path.basename(proj.path), graph);
      } catch (e) { console.error(`Extraction failed [${proj.path}]: ${e.message}`); }
    }
    return results;
  }

  _detectLanguage(projectPath) {
    let jsCount = 0, pyCount = 0;
    const countFiles = (dir, depth = 0) => {
      if (depth > 5) return;
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          if (['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv'].includes(entry.name)) continue;
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) countFiles(full, depth + 1);
          else if (/\.(js|ts|mjs|cjs|jsx|tsx)$/.test(entry.name)) jsCount++;
          else if (/\.(py)$/.test(entry.name)) pyCount++;
        }
      } catch (e) {}
    };
    countFiles(projectPath);
    if (pyCount > jsCount * 2) return 'python';
    return 'javascript';
  }
}

module.exports = { SemanticExtractor };
