// semantic/schema.js v4.0
// 语义图标准定义 - 所有模块的共同语言

const fs = require('fs');
const path = require('path');

const SchemaVersion = {
  major: 4, minor: 0, patch: 0,
  minCompatibleMajor: 4,
  toString() { return `${this.major}.${this.minor}.${this.patch}`; },
  compatibleWith(other) {
    if (!other || typeof other.major !== 'number') return false;
    return other.major === this.major && other.major >= this.minCompatibleMajor;
  },
  canRead(other) {
    if (!other || typeof other.major !== 'number') return false;
    return other.major === this.major && other.minor <= this.minor;
  }
};

const EntityCategories = {
  ABSTRACT:  'abstract',
  CONCRETE:  'concrete',
  INSTANCE:  'instance',
  META:      'meta',
};

const EntityTypes = {
  MCP_TOOL_HANDLER:  { value: 'MCPToolHandler',  category: EntityCategories.ABSTRACT },
  MCP_SERVER:        { value: 'MCPServer',        category: EntityCategories.ABSTRACT },
  MCP_CLIENT:        { value: 'MCPClient',        category: EntityCategories.ABSTRACT },
  PARAMETER:         { value: 'Parameter',         category: EntityCategories.INSTANCE },
  VARIABLE:          { value: 'Variable',          category: EntityCategories.INSTANCE },
  CONSTANT:          { value: 'Constant',          category: EntityCategories.INSTANCE },
  CONFIG_FIELD:      { value: 'ConfigField',       category: EntityCategories.META },
  FILE_OPERATION:    { value: 'FileOperation',     category: EntityCategories.CONCRETE },
  NETWORK_REQUEST:   { value: 'NetworkRequest',    category: EntityCategories.CONCRETE },
  EXEC_SINK:         { value: 'ExecSink',          category: EntityCategories.CONCRETE },
  EVAL_SINK:         { value: 'EvalSink',          category: EntityCategories.CONCRETE },
  LOG_OUTPUT:        { value: 'LogOutput',         category: EntityCategories.CONCRETE },
  VALIDATION_GATE:   { value: 'ValidationGate',    category: EntityCategories.CONCRETE },
  SANITIZER:         { value: 'Sanitizer',         category: EntityCategories.CONCRETE },
  TRUST_GATE:        { value: 'TrustGate',         category: EntityCategories.CONCRETE },
  EXTERNAL_INPUT:    { value: 'ExternalInput',     category: EntityCategories.INSTANCE },
};
const EntityTypeMap = Object.fromEntries(
  Object.entries(EntityTypes).map(([k, v]) => [v.value, { key: k, ...v }])
);
const EntityTypeValues = Object.values(EntityTypes).map(v => v.value);

const RelationTypes = {
  ACCEPTS:        'accepts',
  RETURNS:        'returns',
  FLOWS_INTO:     'flows_into',
  DEPENDS_ON:     'depends_on',
  VALIDATES:      'validates',
  SANITIZES:      'sanitizes',
  CONFIGURES:     'configures',
  INHERITS_FROM:  'inherits_from',
  REFERENCES:     'references',
  INVOKES:        'invokes',
  DELEGATES_TO:   'delegates_to',
  IS_WRAPPER_OF:  'is_wrapper_of',
};

const TaintMode = {
  EXACT:             'exact',
  TRANSFORMED:       'transformed',
  CONTROL_DEPENDENT: 'control',
};

const TaintPropagationRules = {
  'base64_decode':  { preservesTaint: true,  confidenceDecay: 0.1 },
  'base64_encode':  { preservesTaint: true,  confidenceDecay: 0.1 },
  'url_encode':     { preservesTaint: true,  confidenceDecay: 0.05 },
  'json_parse':     { preservesTaint: true,  confidenceDecay: 0.15 },
  'string_concat':  { preservesTaint: true,  confidenceDecay: 0.05 },
  'string_split':   { preservesTaint: true,  confidenceDecay: 0.1 },
  'type_cast':      { preservesTaint: true,  confidenceDecay: 0.0 },
  'sanitize_html':  { preservesTaint: false, confidenceDecay: 0.0 },
  'validate_regex': { preservesTaint: false, confidenceDecay: 0.0 },
  'default':        { preservesTaint: true,  confidenceDecay: 0.2 },
};

const ValidationFailureAction = {
  BLOCK:     'block',
  SANITIZE:  'sanitize',
  LOG:       'log',
  IGNORE:    'ignore',
};
const VALID_FAILURE_ACTIONS = Object.values(ValidationFailureAction);

const ValidatorType = {
  REGEX:          'regex',
  SCHEMA:         'schema',
  WHITELIST:      'whitelist',
  CUSTOM_FUNCTION:'custom_function',
  TYPE_CHECK:     'type_check',
  RANGE_CHECK:    'range_check',
};

const LifecyclePhase = {
  STATIC:  'static',
  DYNAMIC: 'dynamic',
  HYBRID:  'hybrid',
};

const DynamicLoadSource = {
  HTTP_FILE:    'http_file',
  LOCAL_FILE:   'local_file',
  USER_PROMPT:  'user_prompt',
  ENV_VAR:      'env_var',
  NETWORK:      'network',
};

const TrustWeights = {
  [LifecyclePhase.STATIC]:           1.0,
  [LifecyclePhase.HYBRID]:           0.6,
  [LifecyclePhase.DYNAMIC]:          0.3,
  [DynamicLoadSource.HTTP_FILE]:     0.2,
  [DynamicLoadSource.LOCAL_FILE]:    0.7,
  [DynamicLoadSource.USER_PROMPT]:   0.4,
  [DynamicLoadSource.ENV_VAR]:       0.8,
  [DynamicLoadSource.NETWORK]:       0.2,
};

const ParamSources = {
  USER_INPUT:   'user_input',
  CONFIG:       'config',
  ENVIRONMENT:  'environment',
  NETWORK:      'network',
  FILE:         'file',
  UNTRACKED:    'untracked',
  AMBIGUOUS:    'ambiguous',
};

const ParamSourceTrust = {
  [ParamSources.USER_INPUT]:   0.3,
  [ParamSources.NETWORK]:      0.3,
  [ParamSources.AMBIGUOUS]:    0.4,
  [ParamSources.FILE]:         0.6,
  [ParamSources.CONFIG]:       0.7,
  [ParamSources.ENVIRONMENT]:  0.8,
  [ParamSources.UNTRACKED]:    0.1,
};

const SinkSeverity = {
  CRITICAL: { level: 'critical', cweId: 'CWE-78',  desc: '命令执行/代码执行' },
  HIGH:     { level: 'high',     cweId: 'CWE-918', desc: '文件写入/网络请求' },
  MEDIUM:   { level: 'medium',   cweId: 'CWE-22',  desc: '文件读取/日志输出' },
  LOW:      { level: 'low',      cweId: 'CWE-200', desc: '只读操作' },
};

const SinkCWEMap = {
  'exec':            { cwe: 'CWE-78',  severity: 'critical' },
  'execSync':        { cwe: 'CWE-78',  severity: 'critical' },
  'spawn':           { cwe: 'CWE-78',  severity: 'critical' },
  'execFile':        { cwe: 'CWE-78',  severity: 'critical' },
  'eval':            { cwe: 'CWE-94',  severity: 'critical' },
  'Function':        { cwe: 'CWE-94',  severity: 'critical' },
  'fs.writeFile':    { cwe: 'CWE-73',  severity: 'high' },
  'fs.readFile':     { cwe: 'CWE-22',  severity: 'medium' },
  'fetch':           { cwe: 'CWE-918', severity: 'high' },
  'http.request':    { cwe: 'CWE-918', severity: 'high' },
  'console.log':     { cwe: 'CWE-200', severity: 'low' },
  // Python subprocess operations
  'run':           { cwe: 'CWE-78', severity: 'critical' },
  'system':        { cwe: 'CWE-78', severity: 'critical' },
  'popen':         { cwe: 'CWE-78', severity: 'critical' },
  'check_output':  { cwe: 'CWE-78', severity: 'critical' },
  'Popen':         { cwe: 'CWE-78', severity: 'critical' },
  'check_call':    { cwe: 'CWE-78', severity: 'critical' },
  // Python file/network/misc operations
  'read/write':    { cwe: 'CWE-22', severity: 'medium' },
  'read':          { cwe: 'CWE-22', severity: 'medium' },
  'write':         { cwe: 'CWE-22', severity: 'medium' },
  'delete':        { cwe: 'CWE-22', severity: 'high' },
  'get':           { cwe: 'CWE-918', severity: 'high' },
  'post':          { cwe: 'CWE-918', severity: 'high' },
  'put':           { cwe: 'CWE-918', severity: 'high' },
  'request':       { cwe: 'CWE-918', severity: 'high' },
  'urlopen':       { cwe: 'CWE-918', severity: 'high' },
  'compile':       { cwe: 'CWE-94', severity: 'critical' },
  'import':        { cwe: 'CWE-94', severity: 'high' },
  'print':         { cwe: 'CWE-200', severity: 'low' },
  'info':          { cwe: 'CWE-200', severity: 'low' },
  'debug':         { cwe: 'CWE-200', severity: 'low' },
  'warning':       { cwe: 'CWE-200', severity: 'low' },
  'error':         { cwe: 'CWE-200', severity: 'low' },
};

const HIGH_RISK_SINK_TYPES = new Set([
  EntityTypes.EXEC_SINK.value,
  EntityTypes.EVAL_SINK.value,
]);

const McpProtocolVersions = {
  '2024-11-05': { features: ['tools', 'resources', 'prompts'], supportsSampling: false },
  '2025-03-26': { features: ['tools', 'resources', 'prompts', 'roots'], supportsSampling: false },
  '2025-11-25': { features: ['tools', 'resources', 'prompts', 'sampling', 'roots'], supportsSampling: true },
};
const DEFAULT_MCP_VERSION = '2025-11-25';

const IsolationLevel = { PROCESS: 'process', CONTAINER: 'container', VM: 'vm', NONE: 'none' };
const TenantEscapeRisks = {
  FILE_CROSS_READ: 'file_cross_read', FILE_CROSS_WRITE: 'file_cross_write',
  NETWORK_CROSS: 'network_cross', SHARED_STATE: 'shared_state', ENV_LEAK: 'env_leak',
};

const ErrorCodes = {
  E_MISSING_PROJECT: 'E_MISSING_PROJECT', E_EMPTY_ENTITIES: 'E_EMPTY_ENTITIES',
  E_INVALID_ENTITY_TYPE: 'E_INVALID_ENTITY_TYPE', E_INVALID_ENTITY_CATEGORY: 'E_INVALID_ENTITY_CATEGORY',
  E_INVALID_RELATION_TYPE: 'E_INVALID_RELATION_TYPE', E_DANGLING_RELATION_FROM: 'E_DANGLING_RELATION_FROM',
  E_DANGLING_RELATION_TO: 'E_DANGLING_RELATION_TO', E_MISSING_SINK_CWE: 'E_MISSING_SINK_CWE',
  E_INVALID_FAILURE_ACTION: 'E_INVALID_FAILURE_ACTION', E_INVOKES_DEPTH_EXCEEDED: 'E_INVOKES_DEPTH_EXCEEDED',
  E_SCHEMA_INCOMPATIBLE: 'E_SCHEMA_INCOMPATIBLE', W_MISSING_SOURCEMAP: 'W_MISSING_SOURCEMAP',
  W_UNKNOWN_PARAM_SOURCE: 'W_UNKNOWN_PARAM_SOURCE',
};

function createError(code, message, opts = {}) {
  return { code, severity: code.startsWith('W_') ? 'warning' : 'error', message,
    entity: opts.entity || null, relation: opts.relation || null, suggestion: opts.suggestion || null };
}
function errorsToStrings(errors) { return errors.map(e => typeof e === 'string' ? e : `[${e.code}] ${e.message}`); }
function errorsFromStrings(strs) { return strs.map(s => typeof s === 'string' ? createError('E_LEGACY', s) : s); }

function createThreatModel(options = {}) {
  const defaults = {
    mcpProtocol: DEFAULT_MCP_VERSION,
    transport: { type: 'stdio', inheritsEnv: true, localOnly: true, authRequired: false },
    deployment: { mode: 'desktop_app', isProduction: false, autoLoadConfig: false, trustGate: null },
    trustBoundaries: { configSource: 'user_manual', attackerCapabilities: [], tenantIsolation: null },
  };
  return {
    mcpProtocol: options.mcpProtocol || defaults.mcpProtocol,
    transport: { ...defaults.transport, ...(options.transport || {}) },
    deployment: { ...defaults.deployment, ...(options.deployment || {}) },
    trustBoundaries: { ...defaults.trustBoundaries, ...(options.trustBoundaries || {}) },
  };
}

function validateProtocolFeatures(graph) {
  const warnings = [];
  const mcpVersion = graph.threatModel?.mcpProtocol || DEFAULT_MCP_VERSION;
  const versionDef = McpProtocolVersions[mcpVersion];
  if (!versionDef) {
    warnings.push(createError('E_SCHEMA_INCOMPATIBLE', `未知MCP协议版本: ${mcpVersion}`));
    return warnings;
  }
  if (!versionDef.supportsSampling) {
    const samplingEntities = graph.entities.filter(e => e.properties?.mcpFeature === 'sampling');
    if (samplingEntities.length > 0) {
      warnings.push(createError('E_SCHEMA_INCOMPATIBLE',
        `MCP ${mcpVersion} 不支持 sampling，但图谱中存在 ${samplingEntities.length} 个相关实体`));
    }
  }
  return warnings;
}

const MAX_INVOKES_DEPTH = 10;
const MAX_INVOKES_DEPTH_HIGH_RISK = 20;

function validateGraph(graph) {
  const errors = [];
  const entityIds = new Set();
  if (graph._schemaVersion && !SchemaVersion.compatibleWith(graph._schemaVersion)) {
    errors.push(createError('E_SCHEMA_INCOMPATIBLE', `图谱schema版本不兼容`));
  }
  if (!graph.project) errors.push(createError(ErrorCodes.E_MISSING_PROJECT, '缺少 project 字段'));
  if (!graph.entities?.length) errors.push(createError(ErrorCodes.E_EMPTY_ENTITIES, '实体列表为空'));
  for (const entity of (graph.entities || [])) {
    entityIds.add(entity.id);
    const typeDef = EntityTypeMap[entity.type];
    if (!typeDef) {
      errors.push(createError(ErrorCodes.E_INVALID_ENTITY_TYPE, `实体 ${entity.id} 的 type "${entity.type}" 无效`));
      continue;
    }
    if (entity.properties?.category && !Object.values(EntityCategories).includes(entity.properties.category)) {
      errors.push(createError(ErrorCodes.E_INVALID_ENTITY_CATEGORY, `实体 ${entity.id} category无效`));
    }
    if ((entity.type === EntityTypes.EXEC_SINK.value || entity.type === EntityTypes.EVAL_SINK.value) &&
        !entity.properties?.cweId && !SinkCWEMap[entity.properties?.operation]) {
      errors.push(createError(ErrorCodes.E_MISSING_SINK_CWE, `Sink实体 ${entity.id} 缺少 cweId`));
    }
    if (entity.type === EntityTypes.VALIDATION_GATE.value && entity.properties?.onFailure) {
      if (Array.isArray(entity.properties.onFailure)) {
        errors.push(createError(ErrorCodes.E_INVALID_FAILURE_ACTION, `ValidationGate onFailure不允许数组`));
      } else if (!VALID_FAILURE_ACTIONS.includes(entity.properties.onFailure)) {
        errors.push(createError(ErrorCodes.E_INVALID_FAILURE_ACTION, `onFailure "${entity.properties.onFailure}" 无效`));
      }
    }
  }
  const validRelationTypes = Object.values(RelationTypes);
  const invokesChains = {};
  for (const rel of (graph.relations || [])) {
    if (!validRelationTypes.includes(rel.type)) errors.push(createError(ErrorCodes.E_INVALID_RELATION_TYPE, `关系type "${rel.type}" 无效`));
    if (!entityIds.has(rel.from)) errors.push(createError(ErrorCodes.E_DANGLING_RELATION_FROM, `起点 ${rel.from} 不存在`));
    if (!entityIds.has(rel.to)) errors.push(createError(ErrorCodes.E_DANGLING_RELATION_TO, `终点 ${rel.to} 不存在`));
    if (rel.type === RelationTypes.INVOKES) {
      const syncType = rel.properties?.callType || 'sync';
      if (!invokesChains[rel.from]) invokesChains[rel.from] = { depth: 1, callType: syncType };
      invokesChains[rel.from].depth++;
    }
  }
  for (const [entityId, chain] of Object.entries(invokesChains)) {
    const entity = graph.entities.find(e => e.id === entityId);
    const maxDepth = (entity && HIGH_RISK_SINK_TYPES.has(entity.type)) ? MAX_INVOKES_DEPTH_HIGH_RISK : MAX_INVOKES_DEPTH;
    if (chain.depth > maxDepth) errors.push(createError(ErrorCodes.E_INVOKES_DEPTH_EXCEEDED, `INVOKES链深度超限`));
  }
  errors.push(...validateProtocolFeatures(graph));
  for (const entity of (graph.entities || [])) {
    if (entity.location?.sourceMapRequested && !entity.location?.sourceMap) {
      errors.push(createError(ErrorCodes.W_MISSING_SOURCEMAP, `实体 ${entity.id} sourceMap不可用`));
    }
  }
  return { valid: errors.filter(e => e.severity === 'error').length === 0, errors, errorsAsStringArray: errorsToStrings(errors) };
}

function findEntitiesByType(graph, type) { return graph.entities.filter(e => e.type === type); }
function getOutgoingRelations(graph, entityId) { return graph.relations.filter(r => r.from === entityId); }

function traceDataflow(graph, fromEntityId, toType, options = {}) {
  const defaultMaxDepth = options.highRiskSink ? 30 : 15;
  const maxDepth = options.maxDepth || defaultMaxDepth;
  const paths = [];
  const globalVisited = new Set();
  function dfs(currentId, currentPath, depth, accumulatedTaint, accumulatedDecay) {
    if (depth > maxDepth) return;
    if (globalVisited.has(currentId) && depth > maxDepth * 0.8) return;
    globalVisited.add(currentId);
    const outgoing = graph.relations.filter(r =>
      r.from === currentId && (r.type === RelationTypes.FLOWS_INTO || r.type === RelationTypes.RETURNS));
    for (const rel of outgoing) {
      const targetEntity = graph.entities.find(e => e.id === rel.to);
      if (!targetEntity) continue;
      let newTaint = accumulatedTaint, newDecay = accumulatedDecay;
      const transform = rel.properties?.transform;
      if (transform) {
        const rule = TaintPropagationRules[transform] || TaintPropagationRules['default'];
        if (!rule.preservesTaint) newTaint = null; else newDecay += rule.confidenceDecay;
      }
      const newPath = [...currentPath, { entity: targetEntity, relation: rel,
        taintMode: newTaint ? (transform ? TaintMode.TRANSFORMED : TaintMode.EXACT) : null,
        accumulatedDecay: newDecay }];
      if (targetEntity.type === toType) {
        paths.push({ path: newPath, taintPreserved: newTaint !== null, totalDecay: newDecay,
          isDirect: newPath.length === 1,
          hasValidation: newPath.some(step => step.entity.type === EntityTypes.VALIDATION_GATE.value || step.entity.type === EntityTypes.SANITIZER.value) });
      } else { dfs(rel.to, newPath, depth + 1, newTaint, newDecay); }
    }
    globalVisited.delete(currentId);
  }
  dfs(fromEntityId, [], 0, true, 0);
  return paths;
}

function isThreatModelApplicable(graph, requiredConditions) {
  if (!requiredConditions) return true;
  const tm = graph.threatModel;
  if (!tm) return true;
  if (requiredConditions.transportType && tm.transport?.type !== requiredConditions.transportType) return false;
  if (requiredConditions.deploymentMode) {
    const modes = Array.isArray(requiredConditions.deploymentMode) ? requiredConditions.deploymentMode : [requiredConditions.deploymentMode];
    if (!modes.includes(tm.deployment?.mode)) return false;
  }
  if (requiredConditions.configSource) {
    const sources = Array.isArray(requiredConditions.configSource) ? requiredConditions.configSource : [requiredConditions.configSource];
    if (tm.trustBoundaries?.configSource && !sources.includes(tm.trustBoundaries.configSource)) return false;
  }
  if (requiredConditions.excludeDesktopApp && tm.deployment?.mode === 'desktop_app') return false;
  if (requiredConditions.exclude_stdio_standard && tm.transport?.type === 'stdio') return false;
  return true;
}

function generateExample(type) {
  const examples = {
    'tool_injection': () => ({
      project: "MiniMax-MCP", language: "typescript", _schemaVersion: SchemaVersion,
      threatModel: createThreatModel({ transport: { type: "http", inheritsEnv: false, localOnly: false, authRequired: true },
        deployment: { mode: "server_multitenant", isProduction: true },
        trustBoundaries: { attackerCapabilities: ["crafted_tool_output"] } }),
      entities: [
        { id: "fn1", type: EntityTypes.MCP_TOOL_HANDLER.value, name: "search_documents",
          location: { file: "src/tools/search.ts", line: 42, column: 0, sourceMapAvailable: true },
          properties: { category: EntityCategories.ABSTRACT, params: ["query", "limit"] } },
        { id: "var1", type: EntityTypes.VARIABLE.value, name: "result",
          location: { file: "src/tools/search.ts", line: 65, column: 8, sourceMapAvailable: true },
          properties: { category: EntityCategories.INSTANCE, source: "tool_return" } },
        { id: "exec1", type: EntityTypes.EXEC_SINK.value, name: "child_process.exec",
          location: { file: "src/tools/search.ts", line: 78, column: 4, sourceMapAvailable: true },
          properties: { category: EntityCategories.CONCRETE, operation: "exec",
            cweId: SinkCWEMap['exec'].cwe, severity: SinkCWEMap['exec'].severity } },
      ],
      relations: [
        { from: "fn1", to: "var1", type: RelationTypes.RETURNS, properties: { direct: true } },
        { from: "var1", to: "exec1", type: RelationTypes.FLOWS_INTO,
          properties: { validated: false, sanitized: false, taintMode: TaintMode.EXACT } },
      ]
    }),
    'path_traversal': () => ({
      project: "FastMCP", language: "typescript", _schemaVersion: SchemaVersion,
      threatModel: createThreatModel(),
      entities: [
        { id: "fn1", type: EntityTypes.MCP_TOOL_HANDLER.value, name: "read_file",
          location: { file: "src/tools/fs.ts", line: 10, column: 0, sourceMapAvailable: false },
          properties: { category: EntityCategories.ABSTRACT, params: ["path"] } },
        { id: "file1", type: EntityTypes.FILE_OPERATION.value, name: "fs.readFile",
          location: { file: "src/tools/fs.ts", line: 15, column: 4, sourceMapAvailable: false },
          properties: { category: EntityCategories.CONCRETE, operation: "read",
            cweId: SinkCWEMap['fs.readFile'].cwe, severity: SinkCWEMap['fs.readFile'].severity } },
      ],
      relations: [
        { from: "fn1", to: "file1", type: RelationTypes.FLOWS_INTO,
          properties: { validated: false, taintMode: TaintMode.EXACT } },
      ]
    }),
  };
  const generator = examples[type];
  if (!generator) throw new Error(`未知示例类型: ${type}`);
  return generator();
}

module.exports = {
  SchemaVersion, EntityCategories, EntityTypes, EntityTypeMap, EntityTypeValues,
  RelationTypes, TaintMode, TaintPropagationRules, ValidationFailureAction, ValidatorType, VALID_FAILURE_ACTIONS,
  LifecyclePhase, DynamicLoadSource, TrustWeights, ParamSources, ParamSourceTrust,
  SinkSeverity, SinkCWEMap, HIGH_RISK_SINK_TYPES, McpProtocolVersions, DEFAULT_MCP_VERSION,
  IsolationLevel, TenantEscapeRisks, ErrorCodes, createError, errorsToStrings, errorsFromStrings,
  createThreatModel, validateProtocolFeatures, MAX_INVOKES_DEPTH, MAX_INVOKES_DEPTH_HIGH_RISK,
  validateGraph, findEntitiesByType, getOutgoingRelations, traceDataflow, isThreatModelApplicable, generateExample,
};
