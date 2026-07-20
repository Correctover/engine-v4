#!/usr/bin/env node
const path = require('path');
const fs = require('fs');
const ENGINE_DIR = path.join(__dirname);
const PATTERNS_DIR = path.join(ENGINE_DIR, 'patterns');

let passed = 0, failed = 0;
function assert(condition, testName) {
  if (condition) { console.log(`  ✅ ${testName}`); passed++; }
  else { console.log(`  ❌ ${testName}`); failed++; }
}

// Test 1: Schema
console.log('\n📋 Test 1: Schema模块');
try {
  const schema = require(path.join(ENGINE_DIR, 'semantic/schema'));
  assert(schema.SchemaVersion.major === 4, 'SchemaVersion = 4.0.0');
  assert(Object.keys(schema.EntityTypes).length >= 16, `EntityTypes: ${Object.keys(schema.EntityTypes).length} >= 16`);
  assert(Object.keys(schema.RelationTypes).length >= 10, `RelationTypes: ${Object.keys(schema.RelationTypes).length} >= 10`);
  assert(schema.TaintPropagationRules.base64_decode.preservesTaint === true, 'Taint: base64_decode preserves');
  assert(schema.TaintPropagationRules.sanitize_html.preservesTaint === false, 'Taint: sanitize_html cleans');
  assert(schema.SinkCWEMap['exec'].cwe === 'CWE-78', 'SinkCWE: exec→CWE-78');
  assert(schema.SinkCWEMap['fetch'].cwe === 'CWE-918', 'SinkCWE: fetch→CWE-918');
  assert(typeof schema.validateGraph === 'function', 'validateGraph exists');
  assert(typeof schema.traceDataflow === 'function', 'traceDataflow exists');
  assert(typeof schema.createThreatModel === 'function', 'createThreatModel exists');
  assert(typeof schema.generateExample === 'function', 'generateExample exists');
} catch (e) { console.log(`  ❌ Schema load failed: ${e.message}`); failed++; }

// Test 2: Registry
console.log('\n📋 Test 2: Pattern Registry');
try {
  const registry = JSON.parse(fs.readFileSync(path.join(PATTERNS_DIR, 'registry.json'), 'utf-8'));
  assert(registry.patterns.length === 9, `Patterns: ${registry.patterns.length} = 9`);
  assert(registry.patterns.filter(p => p.source === 'agentscope').length === 4, 'AgentScope seeds: 4');
  assert(registry.patterns.filter(p => p.source === 'generic').length === 5, 'Generic: 5');
  assert(registry.stats.total_patterns === 9, `Stats total: ${registry.stats.total_patterns}`);
  for (const p of registry.patterns) {
    const fp = path.join(PATTERNS_DIR, p.file);
    assert(fs.existsSync(fp), `File exists: ${p.file}`);
    const def = JSON.parse(fs.readFileSync(fp, 'utf-8'));
    assert(def.pattern_id === p.pattern_id, `ID match: ${p.pattern_id}`);
  }
} catch (e) { console.log(`  ❌ Registry failed: ${e.message}`); failed++; }

// Test 3: Seed patterns
console.log('\n📋 Test 3: AgentScope Seeds');
const seedTests = [
  { id: 'AS-SSRF-001', cwe: 'CWE-918', category: 'ssrf', severity: 'high' },
  { id: 'AS-RCE-001', cwe: 'CWE-78', category: 'command_injection', severity: 'critical' },
  { id: 'AS-TRUST-BYPASS-001', cwe: 'CWE-863', category: 'trust_boundary_bypass', severity: 'high' },
  { id: 'AS-CONTENT-INJECT-001', cwe: 'CWE-74', category: 'output_injection', severity: 'high' },
];
for (const test of seedTests) {
  try {
    const def = JSON.parse(fs.readFileSync(path.join(PATTERNS_DIR, 'seeds', `${test.id}.json`), 'utf-8'));
    assert(def.pattern_id === test.id, `${test.id}: ID ok`);
    assert(def.cwe === test.cwe, `${test.id}: CWE=${test.cwe}`);
    assert(def.category === test.category, `${test.id}: category ok`);
    assert(def.severity === test.severity, `${test.id}: severity ok`);
    assert(def.source_vulnerability.project === 'AgentScope', `${test.id}: source=AgentScope`);
    assert(def.dataflow_signature !== undefined, `${test.id}: has dataflow_signature`);
    assert(def.constraints !== undefined, `${test.id}: has constraints`);
    assert(def.remediation && def.remediation.length > 20, `${test.id}: has remediation`);
    assert(def.references.length > 0, `${test.id}: has references`);
  } catch (e) { console.log(`  ❌ ${test.id}: ${e.message}`); failed++; }
}

// Test 4: JS adapter
console.log('\n📋 Test 4: JavaScript Adapter');
try {
  const { JavaScriptAdapter } = require(path.join(ENGINE_DIR, 'semantic/adapters/javascript'));
  const adapter = new JavaScriptAdapter();
  assert(typeof adapter.extract === 'function', 'JS adapter has extract()');
} catch (e) { console.log(`  ❌ JS adapter: ${e.message}`); failed++; }

// Test 5: Python adapter
console.log('\n📋 Test 5: Python Adapter');
try {
  const { PythonAdapter } = require(path.join(ENGINE_DIR, 'semantic/adapters/python'));
  const adapter = new PythonAdapter();
  assert(typeof adapter.extract === 'function', 'Python adapter has extract()');
  const tmpDir = '/tmp/test_py_project';
  if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
  fs.writeFileSync(path.join(tmpDir, 'test_mcp.py'), `
import os
from mcp import Server
@server.tool(name="run_command")
async def run_command(cmd: str):
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout
@server.tool(name="read_file")
async def read_file(path: str):
    with open(path, 'r') as f:
        return f.read()
url = os.environ.get("MCP_SERVER_URL")
requests.get(url)
`);
  const graph = adapter.extract(tmpDir, { name: 'test-python-mcp' });
  assert(graph.language === 'python', 'Language=python');
  assert(graph.entities.length > 0, `Entities: ${graph.entities.length} > 0`);
  assert(graph.project === 'test-python-mcp', 'Project name correct');
  const toolHandlers = graph.entities.filter(e => e.type === 'MCPToolHandler');
  assert(toolHandlers.length >= 1, `MCP Tool Handlers: ${toolHandlers.length} >= 1`);
  if (toolHandlers.length > 0) {
    const names = toolHandlers.map(t => t.name);
    assert(names.includes('run_command'), 'Found run_command');
    assert(names.includes('read_file'), 'Found read_file');
  }
  const execSinks = graph.entities.filter(e => e.type === 'ExecSink');
  const fileSinks = graph.entities.filter(e => e.type === 'FileOperation');
  const netSinks = graph.entities.filter(e => e.type === 'NetworkRequest');
  assert(execSinks.length > 0 || fileSinks.length > 0 || netSinks.length > 0,
    `Sinks: exec=${execSinks.length}, file=${fileSinks.length}, net=${netSinks.length}`);
  const envFields = graph.entities.filter(e => e.type === 'ConfigField');
  assert(envFields.length > 0, `Config/env fields: ${envFields.length} > 0`);
  const { validateGraph } = require(path.join(ENGINE_DIR, 'semantic/schema'));
  const validation = validateGraph(graph);
  assert(validation.valid || validation.errors.filter(e => e.severity === 'error').length === 0,
    `Validation: errors=${validation.errors.filter(e=>e.severity==='error').length}, warnings=${validation.errors.filter(e=>e.severity==='warning').length}`);
} catch (e) { console.log(`  ❌ Python adapter: ${e.message}`); failed++; }

// Test 6: Extractor
console.log('\n📋 Test 6: Extractor');
try {
  const { SemanticExtractor } = require(path.join(ENGINE_DIR, 'semantic/extractor'));
  const ext = new SemanticExtractor();
  assert(ext.adapters.javascript !== undefined, 'JS adapter registered');
  assert(ext.adapters.python !== undefined, 'Python adapter registered');
  assert(typeof ext._detectLanguage === 'function', 'Language detection exists');
} catch (e) { console.log(`  ❌ Extractor: ${e.message}`); failed++; }

// Test 7: Matcher
console.log('\n📋 Test 7: Matcher + Confidence');
try {
  const { PatternMatcher } = require(path.join(ENGINE_DIR, 'matching/matcher'));
  const { calculateConfidence } = require(path.join(ENGINE_DIR, 'matching/confidence'));
  assert(typeof PatternMatcher === 'function', 'PatternMatcher exists');
  assert(typeof calculateConfidence === 'function', 'calculateConfidence exists');
  const registry = JSON.parse(fs.readFileSync(path.join(PATTERNS_DIR, 'registry.json'), 'utf-8'));
  const patterns = registry.patterns.filter(p => p.status === 'active')
    .map(p => JSON.parse(fs.readFileSync(path.join(PATTERNS_DIR, p.file), 'utf-8')));
  const matcher = new PatternMatcher(patterns);
  assert(matcher.patterns.length === 9, `Matcher loaded ${matcher.patterns.length} patterns`);
  const { generateExample } = require(path.join(ENGINE_DIR, 'semantic/schema'));
  const exampleGraph = generateExample('tool_injection');
  const findings = matcher.match(exampleGraph);
  assert(Array.isArray(findings), `Match results: ${findings.length} findings`);
} catch (e) { console.log(`  ❌ Matcher: ${e.message}`); failed++; }

// Test 8: Examples
console.log('\n📋 Test 8: Example Graphs');
try {
  const { generateExample, validateGraph } = require(path.join(ENGINE_DIR, 'semantic/schema'));
  const t1 = generateExample('tool_injection');
  assert(validateGraph(t1).valid, 'tool_injection example valid');
  const t2 = generateExample('path_traversal');
  assert(validateGraph(t2).valid, 'path_traversal example valid');
} catch (e) { console.log(`  ❌ Examples: ${e.message}`); failed++; }

console.log('\n' + '='.repeat(50));
console.log(`🏁 Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
console.log('='.repeat(50));
if (failed > 0) process.exit(1);
