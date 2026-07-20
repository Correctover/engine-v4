// patterns/abstractor.js
const fs = require('fs');
const path = require('path');
const { EntityTypes, RelationTypes } = require('../semantic/schema');

class PatternAbstractor {
  constructor(patternsDir) { this.patternsDir = patternsDir; this._nextId = 1; }

  abstract(vulnerability, semanticFragment) {
    const patternId = this._generatePatternId(vulnerability.category);
    const signature = this._extractSignature(semanticFragment);
    const pattern = {
      pattern_id: patternId,
      name: vulnerability.name || `${vulnerability.category} pattern`,
      category: vulnerability.category,
      severity: vulnerability.severity || 'high',
      cwe: vulnerability.cwe || this._inferCWE(vulnerability.category),
      ccs_section: vulnerability.ccs_section || this._inferCCSSection(vulnerability.category),
      source_vulnerability: {
        project: vulnerability.project, issue: vulnerability.issue || null,
        cve: vulnerability.cve || null,
        discovered: vulnerability.discovered || new Date().toISOString().split('T')[0],
        description: vulnerability.description || '',
      },
      migration_count: 0, prerequisites: signature.prerequisites,
      dataflow_signature: signature.dataflow_signature, constraints: signature.constraints,
      remediation: vulnerability.remediation || 'Manual remediation required.',
      references: vulnerability.references || [],
    };
    return pattern;
  }

  savePattern(pattern) {
    const filePath = path.join(this.patternsDir, 'definitions', `${pattern.pattern_id}.json`);
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(pattern, null, 2));
    return filePath;
  }

  updateRegistry(pattern) {
    const registryPath = path.join(this.patternsDir, 'registry.json');
    let registry;
    try { registry = JSON.parse(fs.readFileSync(registryPath, 'utf-8')); }
    catch (e) { registry = { version: "4.0.0", patterns: [], stats: {} }; }
    registry.patterns.push({
      pattern_id: pattern.pattern_id, name: pattern.name,
      file: `definitions/${pattern.pattern_id}.json`, category: pattern.category,
      severity: pattern.severity, cwe: pattern.cwe, status: 'active', migration_count: 0,
    });
    registry.stats.total_patterns = registry.patterns.length;
    registry.stats.last_updated = new Date().toISOString();
    fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2));
    return registryPath;
  }

  _generatePatternId(category) {
    const prefix = {
      path_traversal: 'PATH-TRAVERSAL', command_injection: 'TOOL-INJECTION',
      stdio_injection: 'STDIO-INJECTION', ssrf: 'SSRF-UNCHECKED',
      credential_leak: 'CREDENTIAL-LEAK', output_injection: 'OUTPUT-INJECTION',
      auth_bypass: 'AUTH-BYPASS',
    }[category] || 'UNKNOWN';
    const defsDir = path.join(this.patternsDir, 'definitions');
    let maxNum = 0;
    try {
      const files = fs.readdirSync(defsDir);
      for (const f of files) {
        const match = f.match(new RegExp(`^${prefix.replace(/-/g, '\\-')}-(\\d+)\\.json$`));
        if (match) maxNum = Math.max(maxNum, parseInt(match[1]));
      }
    } catch (e) {}
    return `${prefix}-${String(maxNum + 1).padStart(3, '0')}`;
  }

  _extractSignature(fragment) {
    const entities = fragment.entities || [];
    const relations = fragment.relations || [];
    const entityTypes = [...new Set(entities.map(e => e.type))];
    const sinkEntities = entities.filter(e => ['ExecSink', 'FileOperation', 'NetworkRequest', 'EvalSink'].includes(e.type));
    const hasValidation = entities.some(e => e.type === 'ValidationGate' || e.type === 'Sanitizer');
    return {
      prerequisites: {
        required_entities: entityTypes.map(t => ({ type: t, filters: {} })),
        required_relations: relations.filter(r => r.type === 'flows_into').map(r => ({
          from_type: entities.find(e => e.id === r.from)?.type || 'MCPToolHandler',
          to_type: entities.find(e => e.id === r.to)?.type || 'ExecSink',
          relation: 'flows_into',
        })),
      },
      dataflow_signature: sinkEntities.length > 0 ? {
        source: { type: 'MCPToolHandler', param_filter: {} },
        sink: { type: sinkEntities[0].type },
        must_lack: hasValidation ? [] : ['ValidationGate'],
      } : null,
      constraints: { exclude_test_files: true },
    };
  }

  _inferCWE(category) {
    return { path_traversal: 'CWE-22', command_injection: 'CWE-78', stdio_injection: 'CWE-78',
      ssrf: 'CWE-918', credential_leak: 'CWE-256', output_injection: 'CWE-79', auth_bypass: 'CWE-287' }[category] || 'CWE-20';
  }

  _inferCCSSection(category) {
    return { path_traversal: '4.1', command_injection: '4.2', stdio_injection: '4.3',
      ssrf: '4.4', credential_leak: '4.5', output_injection: '4.6', auth_bypass: '4.7' }[category] || '4.8';
  }
}

module.exports = { PatternAbstractor };
