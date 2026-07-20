// migration/tracker.js
const fs = require('fs');
const path = require('path');

class MigrationTracker {
  constructor(statePath) { this.statePath = statePath; this.state = this._loadState(); }

  _loadState() {
    try {
      if (this.statePath && fs.existsSync(this.statePath)) return JSON.parse(fs.readFileSync(this.statePath, 'utf-8'));
    } catch (e) {}
    return { version: "4.0.0", created_at: new Date().toISOString(), last_updated: new Date().toISOString(),
      patterns: {}, scan_log: [], stats: { total_scans: 0, total_findings: 0, total_patterns: 0, total_projects_scanned: [] } };
  }

  _saveState() {
    if (!this.statePath) return;
    this.state.last_updated = new Date().toISOString();
    this.state.stats.total_patterns = Object.keys(this.state.patterns).length;
    this.state.stats.total_projects_scanned = [...new Set(
      Object.values(this.state.patterns).flatMap(p => Array.isArray(p.projects_found) ? p.projects_found : [...p.projects_found])
    )];
    const dir = path.dirname(this.statePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(this.statePath, JSON.stringify(this.state, null, 2));
  }

  registerSeed(pattern) {
    const id = pattern.pattern_id;
    if (!this.state.patterns[id]) {
      this.state.patterns[id] = {
        pattern_id: id, name: pattern.name, category: pattern.category,
        severity: pattern.severity, cwe: pattern.cwe, ccs_section: pattern.ccs_section,
        seed: { project: pattern.source_vulnerability?.project || 'unknown',
          issue: pattern.source_vulnerability?.issue || null,
          cve: pattern.source_vulnerability?.cve || null,
          discovered: pattern.source_vulnerability?.discovered || new Date().toISOString() },
        migration_chain: [], migration_count: 0, projects_found: [],
        first_seen: null, last_seen: null, registered_at: new Date().toISOString(),
      };
      this._saveState();
      return true;
    }
    return false;
  }

  recordFinding(patternId, projectName, finding) {
    if (!this.state.patterns[patternId]) this.registerSeed({ pattern_id: patternId, name: 'auto-discovered' });
    const pState = this.state.patterns[patternId];
    const now = new Date().toISOString();
    const entry = { project: projectName, date: now, confidence: finding.confidence,
      level: finding.level, file: finding.file, line: finding.line,
      evidence: finding.evidence, cwe: finding.cwe,
      dataflow_path: finding.dataflow_path || null,
      confidence_breakdown: finding.confidence_breakdown || null };
    pState.migration_chain.push(entry);
    pState.migration_count++;
    if (!pState.projects_found.includes(projectName)) pState.projects_found.push(projectName);
    if (!pState.first_seen) pState.first_seen = now;
    pState.last_seen = now;
    this.state.stats.total_findings++;
    this._saveState();
    return entry;
  }

  recordScan(projectName, findingCount, duration) {
    this.state.scan_log.push({ project: projectName, date: new Date().toISOString(),
      finding_count: findingCount, duration_ms: duration });
    this.state.stats.total_scans++;
    this._saveState();
  }

  getMigrationChain(patternId) {
    const p = this.state.patterns[patternId];
    return p ? p.migration_chain : [];
  }

  getPatternHistory(patternId) {
    const p = this.state.patterns[patternId];
    if (!p) return null;
    return { pattern_id: p.pattern_id, name: p.name, seed: p.seed,
      migration_count: p.migration_count, projects: p.projects_found,
      chain: p.migration_chain, first_seen: p.first_seen, last_seen: p.last_seen };
  }

  generateMigrationGraph() {
    return { version: this.state.version, generated_at: new Date().toISOString(),
      summary: { total_patterns: Object.keys(this.state.patterns).length,
        total_findings: this.state.stats.total_findings,
        total_scans: this.state.stats.total_scans,
        total_projects: new Set(Object.values(this.state.patterns).flatMap(p => p.projects_found)).size },
      patterns: Object.values(this.state.patterns).map(p => ({
        pattern_id: p.pattern_id, name: p.name, category: p.category,
        severity: p.severity, cwe: p.cwe, seed: p.seed,
        migration_count: p.migration_count, projects: p.projects_found,
        chain: p.migration_chain, first_seen: p.first_seen, last_seen: p.last_seen })),
      recent_scans: this.state.scan_log.slice(-20) };
  }

  exportMigrationGraph(outputPath) {
    const graph = this.generateMigrationGraph();
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify(graph, null, 2));
    return graph;
  }
}

module.exports = { MigrationTracker };
