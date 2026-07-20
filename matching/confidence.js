// matching/confidence.js
const { SinkSeverity, SinkCWEMap, HIGH_RISK_SINK_TYPES, TaintPropagationRules, ParamSourceTrust, ParamSources, LifecyclePhase, TrustWeights, EntityTypes, RelationTypes } = require('../semantic/schema');

const ConfidenceLevel = {
  CRITICAL: { min: 90, max: 100, label: 'CRITICAL', desc: '几乎确定是漏洞' },
  HIGH:     { min: 70, max: 89,  label: 'HIGH',     desc: '大概率是真洞' },
  MEDIUM:   { min: 50, max: 69,  label: 'MEDIUM',   desc: '需要深入分析' },
  LOW:      { min: 30, max: 49,  label: 'LOW',      desc: '可能是设计建议' },
  INFO:     { min: 0,  max: 29,  label: 'INFO',     desc: '仅供参考' },
};

function scoreToLevel(score) {
  if (score >= 90) return 'CRITICAL';
  if (score >= 70) return 'HIGH';
  if (score >= 50) return 'MEDIUM';
  if (score >= 30) return 'LOW';
  return 'INFO';
}

function calculateConfidence(pattern, matchContext, graph) {
  const breakdown = [];
  let score = 0;
  const baseScores = { path_traversal: 40, command_injection: 50, stdio_injection: 35, ssrf: 35, credential_leak: 35, tool_injection: 45, output_injection: 40 };
  const baseScore = baseScores[pattern.category] || 30;
  score += baseScore;
  breakdown.push({ factor: 'base_score', value: baseScore, pattern: pattern.category });

  if (matchContext.isDirect) { score += 20; breakdown.push({ factor: 'direct_flow', value: 20 }); }
  else { score += 5; breakdown.push({ factor: 'indirect_flow', value: 5 }); }

  if (matchContext.totalDecay > 0) {
    const decayPenalty = Math.round(matchContext.totalDecay * 30);
    score -= decayPenalty;
    breakdown.push({ factor: 'taint_decay', value: -decayPenalty, decay: matchContext.totalDecay });
  }
  if (matchContext.taintPreserved === false) { score -= 25; breakdown.push({ factor: 'taint_cleansed', value: -25 }); }

  if (!matchContext.hasValidation) { score += 15; breakdown.push({ factor: 'no_validation', value: 15 }); }
  else if (matchContext.hasPartialValidation) { score -= 10; breakdown.push({ factor: 'partial_validation', value: -10 }); }
  else { score -= 25; breakdown.push({ factor: 'full_validation', value: -25 }); }

  const sinkEntity = matchContext.sinkEntity;
  if (sinkEntity) {
    if (HIGH_RISK_SINK_TYPES.has(sinkEntity.type)) { score += 10; breakdown.push({ factor: 'high_risk_sink', value: 10 }); }
    const op = sinkEntity.properties?.operation;
    if (op && SinkCWEMap[op]) { score += 5; breakdown.push({ factor: 'precise_cwe', value: 5, cwe: SinkCWEMap[op].cwe }); }
  }

  if (matchContext.paramSource) {
    const trust = ParamSourceTrust[matchContext.paramSource] || 0.5;
    const sourceBonus = Math.round((1 - trust) * 15);
    score += sourceBonus;
    breakdown.push({ factor: 'param_source_risk', value: sourceBonus, source: matchContext.paramSource, trust });
  }

  const tm = graph.threatModel;
  if (tm) {
    if (tm.deployment?.mode === 'server_multitenant') { score += 15; breakdown.push({ factor: 'multitenant', value: 15 }); }
    if (tm.transport?.type === 'http' || tm.transport?.type === 'sse') { score += 10; breakdown.push({ factor: 'remote_transport', value: 10 }); }
    if (tm.deployment?.mode === 'desktop_app') { score -= 15; breakdown.push({ factor: 'desktop_app', value: -15 }); }
    if (tm.transport?.type === 'stdio' && pattern.category === 'credential_leak') { score -= 25; breakdown.push({ factor: 'stdio_standard_behavior', value: -25 }); }
    if (tm.deployment?.trustGate) { score -= 10; breakdown.push({ factor: 'trust_gate_present', value: -10 }); }
  }

  if (matchContext.isTestFile) { score -= 20; breakdown.push({ factor: 'test_file', value: -20 }); }
  if (matchContext.isDocFile) { score -= 15; breakdown.push({ factor: 'doc_file', value: -15 }); }
  if (pattern.source_vulnerability?.cve || pattern.migration_count > 0) { score += 5; breakdown.push({ factor: 'known_pattern', value: 5 }); }
  if (pattern.migration_count > 2) { score += 5; breakdown.push({ factor: 'well_validated_pattern', value: 5 }); }

  const finalScore = Math.max(0, Math.min(100, Math.round(score)));
  return { score: finalScore, level: scoreToLevel(finalScore), levelInfo: ConfidenceLevel[scoreToLevel(finalScore)], breakdown };
}

module.exports = { ConfidenceLevel, scoreToLevel, calculateConfidence };
