// matching/matcher.js
const { EntityTypes, RelationTypes, traceDataflow, isThreatModelApplicable, HIGH_RISK_SINK_TYPES, TaintMode } = require('../semantic/schema');
const { calculateConfidence } = require('./confidence');

class PatternMatcher {
  constructor(patterns) { this.patterns = patterns; }

  match(graph, options = {}) {
    const allFindings = [];
    const minConfidence = options.minConfidence || 0;
    for (const pattern of this.patterns) {
      try {
        const findings = this._matchPattern(pattern, graph);
        allFindings.push(...findings);
      } catch (e) {
        allFindings.push({ pattern_id: pattern.pattern_id, pattern_name: pattern.name, error: e.message, confidence: 0, level: 'INFO' });
      }
    }
    allFindings.sort((a, b) => b.confidence - a.confidence);
    return options.maxFindings ? allFindings.filter(f => f.confidence >= minConfidence).slice(0, options.maxFindings) : allFindings.filter(f => f.confidence >= minConfidence);
  }

  _matchPattern(pattern, graph) {
    if (!isThreatModelApplicable(graph, pattern.constraints)) return [];
    if (!pattern.dataflow_signature) return this._matchConfigPattern(pattern, graph);
    if (!this._checkPrerequisites(pattern, graph)) return [];
    const flowMatches = this._matchDataflow(pattern, graph);
    if (flowMatches.length === 0) return [];
    return flowMatches.filter(m => this._checkConstraints(pattern, m, graph)).map(m => {
      const confResult = calculateConfidence(pattern, m, graph);
      return { pattern_id: pattern.pattern_id, pattern_name: pattern.name, category: pattern.category,
        severity: pattern.severity, cwe: pattern.cwe, ccs_section: pattern.ccs_section,
        confidence: confResult.score, level: confResult.level, confidence_breakdown: confResult.breakdown,
        evidence: m.evidence, dataflow_path: m.dataflowPath, taint_preserved: m.taintPreserved,
        has_validation: m.hasValidation, file: m.file, line: m.line, sink_entity: m.sinkEntity,
        remediation: pattern.remediation, references: pattern.references, migration_history: pattern._migration_chain || [] };
    });
  }

  _checkPrerequisites(pattern, graph) {
    const prereqs = pattern.prerequisites;
    if (!prereqs?.required_entities) return true;
    for (const req of prereqs.required_entities) {
      const found = graph.entities.filter(e => {
        if (e.type !== req.type) return false;
        if (req.filters) { for (const [k, v] of Object.entries(req.filters)) {
          if (v instanceof RegExp) { if (!v.test(e.properties?.[k] || e.name || '')) return false; }
          else if (e.properties?.[k] !== v) return false;
        }}
        return true;
      });
      if (found.length === 0) return false;
    }
    if (prereqs.required_relations) {
      for (const rel of prereqs.required_relations) {
        const fromE = graph.entities.filter(e => e.type === rel.from_type);
        const toE = graph.entities.filter(e => e.type === rel.to_type);
        if (!fromE.some(from => graph.relations.some(r => r.from === from.id && r.type === rel.relation && toE.some(to => r.to === to.id)))) return false;
      }
    }
    return true;
  }

  _matchDataflow(pattern, graph) {
    const sig = pattern.dataflow_signature;
    const matches = [];
    const sourceFilter = sig.source.param_filter || {};
    const sources = graph.entities.filter(e => {
      if (e.type !== sig.source.type) return false;
      if (sourceFilter.isPathLike) { const params = e.properties?.params || []; if (!params.some(p => p.isPathLike || p.name?.match(/path|file|dir/i))) return false; }
      if (sourceFilter.isCommandLike) { const params = e.properties?.params || []; if (!params.some(p => p.isCommandLike || p.name?.match(/cmd|command|exec/i))) return false; }
      return true;
    });
    const sinks = graph.entities.filter(e => e.type === sig.sink.type);
    for (const source of sources) {
      for (const sink of sinks) {
        const isHighRisk = HIGH_RISK_SINK_TYPES.has(sink.type);
        const paths = traceDataflow(graph, source.id, sig.sink.type, { maxDepth: isHighRisk ? 20 : 15, highRiskSink: isHighRisk });
        for (const pathResult of paths) {
          const lacksValidation = this._checkMustLack(sig.must_lack, pathResult, graph);
          if (sig.must_lack.length === 0 || lacksValidation) {
            matches.push({ evidence: `${source.type}[${source.name}] -> ${sink.type}[${sink.name}]`,
              dataflowPath: pathResult.path.map(p => ({ entity: p.entity.id, type: p.entity.type, name: p.entity.name, relation: p.relation?.type, taintMode: p.taintMode })),
              sinkEntity: sink, file: source.location?.file || sink.location?.file, line: source.location?.line || sink.location?.line,
              isDirect: pathResult.isDirect, hasValidation: pathResult.hasValidation, hasPartialValidation: false,
              taintPreserved: pathResult.taintPreserved, totalDecay: pathResult.totalDecay,
              isTestFile: this._isTestFile(source.location?.file || sink.location?.file),
              paramSource: source.properties?.params?.[0]?.source });
          }
        }
      }
    }
    return matches;
  }

  _checkMustLack(mustLack, pathResult, graph) {
    if (!mustLack || mustLack.length === 0) return true;
    for (const lacking of mustLack) { if (pathResult.path.some(step => step.entity.type === lacking)) return false; }
    return true;
  }

  _checkConstraints(pattern, match, graph) {
    const c = pattern.constraints;
    if (!c) return true;
    if (c.exclude_test_files && match.isTestFile) return false;
    if (c.transport && graph.threatModel?.transport?.type !== c.transport) return false;
    if (c.deployment_mode) {
      const modes = Array.isArray(c.deployment_mode) ? c.deployment_mode : [c.deployment_mode];
      if (!modes.includes(graph.threatModel?.deployment?.mode)) return false;
    }
    if (c.exclude_desktop_app && graph.threatModel?.deployment?.mode === 'desktop_app') return false;
    if (c.exclude_stdio_standard && graph.threatModel?.transport?.type === 'stdio' && pattern.category === 'credential_leak') return false;
    return true;
  }

  _matchConfigPattern(pattern, graph) {
    const findings = [];
    if (pattern.category === 'credential_leak') {
      const envEntities = graph.entities.filter(e => e.type === EntityTypes.CONFIG_FIELD.value && e.properties?.is_sensitive);
      for (const entity of envEntities) {
        const match = { evidence: `敏感环境变量引用: ${entity.name}`, file: entity.location?.file, line: entity.location?.line,
          isDirect: true, hasValidation: false, hasPartialValidation: false, taintPreserved: true, totalDecay: 0,
          isTestFile: this._isTestFile(entity.location?.file), paramSource: 'environment', sinkEntity: entity };
        if (this._checkConstraints(pattern, match, graph)) {
          const confResult = calculateConfidence(pattern, match, graph);
          findings.push({ pattern_id: pattern.pattern_id, pattern_name: pattern.name, category: pattern.category,
            severity: pattern.severity, cwe: pattern.cwe, ccs_section: pattern.ccs_section,
            confidence: confResult.score, level: confResult.level, confidence_breakdown: confResult.breakdown,
            evidence: match.evidence, file: match.file, line: match.line,
            remediation: pattern.remediation, references: pattern.references, migration_history: [] });
        }
      }
    }
    return findings;
  }

  _isTestFile(filePath) { return filePath ? /test|spec|__tests__|\.test\.|\.spec\.|\.e2e\./i.test(filePath) : false; }
}

module.exports = { PatternMatcher };
