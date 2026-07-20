#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { SemanticExtractor } = require('./semantic/extractor');
const { PatternMatcher } = require('./matching/matcher');
const { MigrationTracker } = require('./migration/tracker');
const { PatternAbstractor } = require('./patterns/abstractor');
const { validateGraph, SchemaVersion } = require('./semantic/schema');

const ENGINE_DIR = __dirname;
const PATTERNS_DIR = path.join(ENGINE_DIR, 'patterns');
const OUTPUT_DIR = path.join(ENGINE_DIR, '..', 'output');

function loadPatterns() {
  const registryPath = path.join(PATTERNS_DIR, 'registry.json');
  const registry = JSON.parse(fs.readFileSync(registryPath, 'utf-8'));
  return registry.patterns.filter(p => p.status === 'active').map(p => JSON.parse(fs.readFileSync(path.join(PATTERNS_DIR, p.file), 'utf-8')));
}

function parseArgs(argv) {
  const args = argv.slice(2);
  const command = args[0], target = args[1], options = {};
  for (let i = 2; i < args.length; i++) {
    if (args[i] === '--format') options.format = args[++i];
    else if (args[i] === '--output') options.output = args[++i];
    else if (args[i] === '--min-confidence') options.minConfidence = parseInt(args[++i]);
    else if (args[i] === '--name') options.name = args[++i];
    else if (args[i] === '--max-findings') options.maxFindings = parseInt(args[++i]);
    else if (args[i] === '--quiet') options.quiet = true;
    else if (args[i] === '--threat-model') options.threatModelPath = args[++i];
  }
  return { command, target, options };
}

function toText(findings) {
  if (findings.length === 0) return 'No security issues found.\n';
  const lines = [`\nCorrectover Pattern Migration Engine v${SchemaVersion}`, `   Found ${findings.length} issues\n`, '-'.repeat(60)];
  for (const f of findings) {
    const icon = f.level === 'CRITICAL' ? '🔴' : f.level === 'HIGH' ? '🟠' : f.level === 'MEDIUM' ? '🟡' : f.level === 'LOW' ? '🔵' : '⚪';
    lines.push(`\n${icon} [${f.level}] ${f.pattern_name} (${f.confidence})`);
    lines.push(`   Pattern: ${f.pattern_id} | CWE: ${f.cwe} | CCS: ${f.ccs_section}`);
    lines.push(`   File: ${f.file || 'unknown'}:${f.line || '?'}`);
    lines.push(`   Evidence: ${f.evidence}`);
    if (f.dataflow_path) lines.push(`   Dataflow: ${f.dataflow_path.map(p => `${p.type}[${p.name}]`).join(' -> ')}`);
    if (f.remediation) lines.push(`   Remediation: ${f.remediation.substring(0, 100)}...`);
  }
  lines.push('\n' + '-'.repeat(60));
  const summary = {};
  for (const f of findings) summary[f.level] = (summary[f.level] || 0) + 1;
  lines.push(`Summary: ${Object.entries(summary).map(([k,v]) => `${k}=${v}`).join(' | ')}`);
  return lines.join('\n');
}

function toMarkdown(findings) {
  const lines = [`# Correctover Security Scan Report`, `\n**Scan Time**: ${new Date().toISOString()}`, `**Schema**: ${SchemaVersion}`, `**Findings**: ${findings.length}\n`];
  for (const f of findings) {
    lines.push(`## ${f.pattern_name}`);
    lines.push(`- **Severity**: ${f.level} (${f.confidence}/100) | **CWE**: ${f.cwe}`);
    lines.push(`- **Location**: \`${f.file}:${f.line}\``);
    lines.push(`- **Evidence**: ${f.evidence}`);
    if (f.dataflow_path) lines.push(`- **Dataflow**: ${f.dataflow_path.map(p => `\`${p.type}[${p.name}]\``).join(' -> ')}`);
    lines.push(`- **Remediation**: ${f.remediation || 'N/A'}\n`);
  }
  return lines.join('\n');
}

function toSARIF(findings) {
  return { "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0", runs: [{ tool: { driver: { name: "Correctover Pattern Migration Engine", version: String(SchemaVersion),
      informationUri: "https://correctover.com",
      rules: [...new Set(findings.map(f => f.pattern_id))].map(pid => ({ id: pid, shortDescription: { text: findings.find(f => f.pattern_id === pid)?.pattern_name || pid } })) } },
      results: findings.map(f => ({ ruleId: f.pattern_id, level: f.level === 'CRITICAL' ? 'error' : f.level === 'HIGH' ? 'error' : 'warning',
        message: { text: f.evidence },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file || 'unknown' }, region: { startLine: f.line || 1 } } }],
        properties: { confidence: f.confidence, cwe: f.cwe, ccs_section: f.ccs_section } })) }] };
}

function formatFindings(findings, format) {
  switch (format) { case 'json': return JSON.stringify(findings, null, 2); case 'sarif': return JSON.stringify(toSARIF(findings), null, 2); case 'markdown': return toMarkdown(findings); default: return toText(findings); }
}

function main() {
  const { command, target, options } = parseArgs(process.argv);
  if (!command) {
    console.log(`Correctover Pattern Migration Engine v${SchemaVersion}\n\nUsage:\n  node cli.js scan <path> [options]\n  node cli.js info <path>\n  node cli.js patterns\n\nOptions:\n  --format text|json|sarif|markdown\n  --output <file>\n  --min-confidence <0-100>\n  --name <name>`);
    return;
  }
  switch (command) {
    case 'scan': {
      if (!target) { console.error('Error: project path required'); process.exit(1); }
      const projectPath = path.resolve(target);
      if (!fs.existsSync(projectPath)) { console.error(`Error: path not found ${projectPath}`); process.exit(1); }
      const startTime = Date.now();
      let threatModel = null;
      if (options.threatModelPath) threatModel = JSON.parse(fs.readFileSync(options.threatModelPath, 'utf-8'));
      if (!options.quiet) console.error('Extracting semantic graph...');
      const extractor = new SemanticExtractor();
      const graph = extractor.extract(projectPath, { name: options.name, threatModel });
      if (!options.quiet) console.error(`   Entities: ${graph.entities.length} | Relations: ${graph.relations.length}`);
      if (!options.quiet) console.error('Matching attack patterns...');
      const patterns = loadPatterns();
      const matcher = new PatternMatcher(patterns);
      const findings = matcher.match(graph, { minConfidence: options.minConfidence || 0, maxFindings: options.maxFindings });
      const tracker = new MigrationTracker(path.join(OUTPUT_DIR, 'migration-state.json'));
      for (const p of patterns) tracker.registerSeed(p);
      for (const f of findings) tracker.recordFinding(f.pattern_id, options.name || path.basename(projectPath), f);
      tracker.recordScan(options.name || path.basename(projectPath), findings.length, Date.now() - startTime);
      const output = formatFindings(findings, options.format || 'text');
      if (options.output) { const d = path.dirname(options.output); if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); fs.writeFileSync(options.output, output); if (!options.quiet) console.error(`\nResults written to ${options.output}`); }
      else console.log(output);
      tracker.exportMigrationGraph(path.join(OUTPUT_DIR, 'migration-graph.json'));
      if (!options.quiet) console.error(`\nDuration: ${Date.now() - startTime}ms`);
      break;
    }
    case 'info': {
      if (!target) { console.error('Error: project path required'); process.exit(1); }
      const graph = new SemanticExtractor().extract(path.resolve(target), { name: options.name });
      const validation = validateGraph(graph);
      console.log(JSON.stringify({ project: graph.project, language: graph.language, threatModel: graph.threatModel,
        stats: { entities: graph.entities.length, relations: graph.relations.length,
          by_type: graph.entities.reduce((a, e) => { a[e.type] = (a[e.type]||0)+1; return a; }, {}) },
        validation: { valid: validation.valid, errors: validation.errorsAsStringArray } }, null, 2));
      break;
    }
    case 'patterns': {
      const patterns = loadPatterns();
      console.log(`\nCorrectover Pattern Library (${patterns.length} patterns)\n`);
      for (const p of patterns) {
        const icon = p.severity === 'critical' ? '🔴' : p.severity === 'high' ? '🟠' : '🟡';
        console.log(`  ${icon} ${p.pattern_id}: ${p.name}\n     CWE: ${p.cwe} | Source: ${p.source_vulnerability?.project || 'N/A'} | Migrations: ${p.migration_count}\n`);
      }
      break;
    }
    default: console.error(`Unknown command: ${command}`); process.exit(1);
  }
}

main();
