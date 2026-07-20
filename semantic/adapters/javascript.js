// semantic/adapters/javascript.js
const fs = require('fs');
const path = require('path');
const { EntityTypes, RelationTypes, ParamSources, SinkSeverity } = require('../schema');

const DANGER_SINKS = {
  'fs.readFile': { type: EntityTypes.FILE_OPERATION.value, op: 'read', severity: SinkSeverity.MEDIUM.level },
  'fs.readFileSync': { type: EntityTypes.FILE_OPERATION.value, op: 'read', severity: SinkSeverity.MEDIUM.level },
  'fs.writeFile': { type: EntityTypes.FILE_OPERATION.value, op: 'write', severity: SinkSeverity.HIGH.level },
  'fs.writeFileSync': { type: EntityTypes.FILE_OPERATION.value, op: 'write', severity: SinkSeverity.HIGH.level },
  'fs.unlink': { type: EntityTypes.FILE_OPERATION.value, op: 'delete', severity: SinkSeverity.HIGH.level },
  'fs.unlinkSync': { type: EntityTypes.FILE_OPERATION.value, op: 'delete', severity: SinkSeverity.HIGH.level },
  'fs.createReadStream': { type: EntityTypes.FILE_OPERATION.value, op: 'read', severity: SinkSeverity.MEDIUM.level },
  'fs.createWriteStream': { type: EntityTypes.FILE_OPERATION.value, op: 'write', severity: SinkSeverity.HIGH.level },
  'fs.rm': { type: EntityTypes.FILE_OPERATION.value, op: 'delete', severity: SinkSeverity.HIGH.level },
  'fs.rename': { type: EntityTypes.FILE_OPERATION.value, op: 'write', severity: SinkSeverity.HIGH.level },
  'child_process.exec': { type: EntityTypes.EXEC_SINK.value, op: 'exec', severity: SinkSeverity.CRITICAL.level },
  'child_process.execSync': { type: EntityTypes.EXEC_SINK.value, op: 'execSync', severity: SinkSeverity.CRITICAL.level },
  'child_process.spawn': { type: EntityTypes.EXEC_SINK.value, op: 'spawn', severity: SinkSeverity.CRITICAL.level },
  'child_process.spawnSync': { type: EntityTypes.EXEC_SINK.value, op: 'spawnSync', severity: SinkSeverity.CRITICAL.level },
  'child_process.execFile': { type: EntityTypes.EXEC_SINK.value, op: 'execFile', severity: SinkSeverity.CRITICAL.level },
  'eval': { type: EntityTypes.EVAL_SINK.value, op: 'eval', severity: SinkSeverity.CRITICAL.level },
  'Function': { type: EntityTypes.EVAL_SINK.value, op: 'Function', severity: SinkSeverity.CRITICAL.level },
  'vm.runInContext': { type: EntityTypes.EVAL_SINK.value, op: 'eval', severity: SinkSeverity.CRITICAL.level },
  'fetch': { type: EntityTypes.NETWORK_REQUEST.value, op: 'request', severity: SinkSeverity.HIGH.level },
  'http.get': { type: EntityTypes.NETWORK_REQUEST.value, op: 'get', severity: SinkSeverity.HIGH.level },
  'https.get': { type: EntityTypes.NETWORK_REQUEST.value, op: 'get', severity: SinkSeverity.HIGH.level },
  'http.request': { type: EntityTypes.NETWORK_REQUEST.value, op: 'request', severity: SinkSeverity.HIGH.level },
  'axios.get': { type: EntityTypes.NETWORK_REQUEST.value, op: 'get', severity: SinkSeverity.HIGH.level },
  'axios.post': { type: EntityTypes.NETWORK_REQUEST.value, op: 'post', severity: SinkSeverity.HIGH.level },
  'console.log': { type: EntityTypes.LOG_OUTPUT.value, op: 'log', severity: SinkSeverity.LOW.level },
  'console.error': { type: EntityTypes.LOG_OUTPUT.value, op: 'error', severity: SinkSeverity.LOW.level },
};

const VALIDATION_FNS = [
  'path.resolve', 'path.normalize', 'path.join', 'fs.realpathSync', 'fs.realpath',
  'sanitize', 'validate', 'escape', 'screen_path', 'contains_path_traversal',
  'isAbsolute', 'is_absolute', 'allowedOrigins', 'url_whitelist', 'domain_check',
  'isInternalIP', 'isPrivateIP', 'isLoopback',
];

const MCP_HANDLER_PATTERNS = [
  /\.tool\s*\(\s*['"]([^'"]+)['"]/g, /\.registerTool\s*\(\s*['"]([^'"]+)['"]/g,
  /setRequestHandler\s*\(\s*CallToolRequestSchema/g, /server\.tool\s*\(\s*['"]([^'"]+)['"]/g,
  /@mcp\.tool/g, /@server\.tool/g, /handleToolCall/g, /onToolCall/g, /toolHandler/g, /ListToolsRequestSchema/g,
];

const USER_INPUT_KEYWORDS = ['params', 'args', 'arguments', 'input', 'toolInput', 'tool_input', 'request.params', 'ctx.params', 'ctx.args', 'req.params', 'req.body', 'req.query', 'toolCall', 'tool_call'];
const CONFIG_KEYWORDS = ['config', 'options', 'settings', 'prefs', 'this.config', 'this.options'];
const ENV_KEYWORDS = ['process.env', 'env.', 'getenv', 'environ'];

class JavaScriptAdapter {
  constructor() { this._counter = 0; }
  _nextId(prefix) { return `${prefix}_${++this._counter}`; }

  extract(projectPath, meta = {}) {
    this._counter = 0;
    const graph = {
      project: meta.name || path.basename(projectPath), language: 'javascript',
      threatModel: meta.threatModel || this._detectThreatModel(projectPath),
      entities: [], relations: [],
    };
    for (const file of this._collectFiles(projectPath)) {
      try {
        const content = fs.readFileSync(file, 'utf-8');
        this._extractFromFile(content, path.relative(projectPath, file), graph);
      } catch (e) {}
    }
    return graph;
  }

  _collectFiles(dir, depth = 0) {
    if (depth > 10) return [];
    const SKIP = new Set(['node_modules', 'dist', 'build', '.git', '__pycache__', '.next', 'coverage']);
    const files = [];
    try {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.name.startsWith('.') && entry.name !== '.env') continue;
        if (SKIP.has(entry.name)) continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) files.push(...this._collectFiles(full, depth + 1));
        else if (/\.(js|ts|mjs|cjs|jsx|tsx)$/.test(entry.name) && !entry.name.endsWith('.d.ts')) files.push(full);
      }
    } catch (e) {}
    return files;
  }

  _extractFromFile(content, relPath, graph) {
    const isMCPFile = MCP_HANDLER_PATTERNS.some(p => p.test(content));
    const functions = this._extractFunctions(content, relPath, isMCPFile);
    graph.entities.push(...functions.entities); graph.relations.push(...functions.relations);
    const sinks = this._extractDangerSinks(content, relPath);
    graph.entities.push(...sinks.entities);
    const gates = this._extractValidationGates(content, relPath);
    graph.entities.push(...gates.entities);
    const flowEdges = this._buildDataFlowEdges(content, relPath, functions.entities, sinks.entities, gates.entities);
    graph.relations.push(...flowEdges);
    const valEdges = this._buildValidationEdges(content, relPath, gates.entities, sinks.entities);
    graph.relations.push(...valEdges);
    const envRefs = this._extractEnvReferences(content, relPath);
    graph.entities.push(...envRefs.entities); graph.relations.push(...envRefs.relations);
  }

  _extractFunctions(content, relPath, isMCPFile) {
    const entities = []; const relations = [];
    const funcPatterns = [
      /(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)/g,
      /(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*(?:=>|:.*=>)/g,
      /(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)/g,
      /(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{/g,
    ];
    const seenFuncs = new Set();
    for (const pattern of funcPatterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const name = match[1];
        if (seenFuncs.has(name)) continue;
        seenFuncs.add(name);
        const rawParams = match[2] || '';
        const params = rawParams.split(',').map(p => p.trim().replace(/^[\[{].*?[\}]]\s*=?\s*/, '').replace(/:.*$/, '').replace(/=.*$/, '').trim()).filter(p => p && p.length > 0 && p.length < 50);
        const line = content.substring(0, match.index).split('\n').length;
        const contextWindow = content.substring(Math.max(0, match.index - 500), match.index + match[0].length + 200);
        const isMCPHandler = isMCPFile && MCP_HANDLER_PATTERNS.some(p => new RegExp(p.source, p.flags).test(contextWindow));
        const entityId = this._nextId('fn');
        entities.push({ id: entityId, type: EntityTypes.MCP_TOOL_HANDLER.value, name,
          location: { file: relPath, line, column: 0 },
          properties: { is_mcp_handler: isMCPHandler,
            params: params.map(p => ({ name: p, source: this._classifyParamSource(p, content, match.index),
              isPathLike: /path|file|dir|folder|filepath|filename|uri/i.test(p),
              isCommandLike: /cmd|command|exec|shell|script|code|expr/i.test(p),
              isUrlLike: /url|uri|endpoint|host|addr/i.test(p) })),
            raw_params: rawParams, param_count: params.length } });
        for (const p of params) {
          const paramId = this._nextId('param');
          entities.push({ id: paramId, type: EntityTypes.PARAMETER, name: p,
            location: { file: relPath, line, column: 0 },
            properties: { source: this._classifyParamSource(p, content, match.index),
              isPathLike: /path|file|dir|folder/i.test(p), isCommandLike: /cmd|command|exec/i.test(p), isUrlLike: /url|uri|endpoint/i.test(p) } });
          relations.push({ from: entityId, to: paramId, type: RelationTypes.ACCEPTS, properties: { param_name: p } });
        }
      }
    }
    return { entities, relations };
  }

  _extractDangerSinks(content, relPath) {
    const entities = [];
    for (const [pattern, info] of Object.entries(DANGER_SINKS)) {
      const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(`(?:^|[^\\w.])${escaped}\\s*\\(`, 'g');
      let match;
      while ((match = regex.exec(content)) !== null) {
        const line = content.substring(0, match.index).split('\n').length;
        const argStr = this._extractCallArgs(content, match.index + match[0].length);
        entities.push({ id: this._nextId('sink'), type: typeof info.type === 'string' ? info.type : info.type.value,
          name: pattern, location: { file: relPath, line, column: 0 },
          properties: { operation: info.op, severity: info.severity, raw_args: argStr.substring(0, 300),
            has_path_arg: /path|file|dir/i.test(argStr), has_url_arg: /url|uri|endpoint/i.test(argStr),
            has_cmd_arg: /cmd|command|exec|shell/i.test(argStr), has_env_ref: /process\.env|env\[/.test(argStr) } });
      }
    }
    return { entities };
  }

  _extractValidationGates(content, relPath) {
    const entities = [];
    for (const fn of VALIDATION_FNS) {
      const escaped = fn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(`(?:^|[^\\w.])${escaped}\\s*\\(`, 'g');
      let match;
      while ((match = regex.exec(content)) !== null) {
        const line = content.substring(0, match.index).split('\n').length;
        const argStr = this._extractCallArgs(content, match.index + match[0].length);
        entities.push({ id: this._nextId('gate'), type: EntityTypes.VALIDATION_GATE, name: fn,
          location: { file: relPath, line, column: 0 },
          properties: { validation_type: fn, raw_args: argStr.substring(0, 200) } });
      }
    }
    return { entities };
  }

  _extractEnvReferences(content, relPath) {
    const entities = []; const relations = [];
    const envRegex = /process\.env\.(\w+)|process\.env\[['"](\w+)['"]\]/g;
    let match;
    while ((match = envRegex.exec(content)) !== null) {
      const envName = match[1] || match[2];
      const line = content.substring(0, match.index).split('\n').length;
      entities.push({ id: this._nextId('env'), type: EntityTypes.CONFIG_FIELD, name: `process.env.${envName}`,
        location: { file: relPath, line, column: 0 },
        properties: { env_key: envName, is_sensitive: /KEY|SECRET|TOKEN|PASSWORD|PRIVATE|CREDENTIAL|AUTH/i.test(envName), source: ParamSources.ENVIRONMENT } });
    }
    return { entities, relations };
  }

  _buildDataFlowEdges(content, relPath, functions, sinks, gates) {
    const edges = [];
    for (const sink of sinks) {
      const containingFunc = functions.find(f => f.location.line < sink.location.line && sink.location.line - f.location.line < 80 && f.location.file === sink.location.file);
      if (containingFunc) {
        const paramNames = (containingFunc.properties?.params || []).map(p => p.name);
        const directFlow = paramNames.some(p => p.length > 1 && sink.properties?.raw_args?.includes(p));
        edges.push({ from: containingFunc.id, to: sink.id, type: RelationTypes.FLOWS_INTO,
          properties: { direct: directFlow, param_match: paramNames.filter(p => p.length > 1 && sink.properties?.raw_args?.includes(p)) } });
      }
    }
    return edges;
  }

  _buildValidationEdges(content, relPath, gates, sinks) {
    const edges = [];
    for (const gate of gates) {
      for (const sink of sinks) {
        if (gate.location.file !== sink.location.file) continue;
        if (Math.abs(gate.location.line - sink.location.line) > 30) continue;
        const gateArgs = gate.properties?.raw_args || ''; const sinkArgs = sink.properties?.raw_args || '';
        if (gateArgs.split(/[,\s]+/).some(arg => arg.length > 2 && sinkArgs.includes(arg))) {
          edges.push({ from: gate.id, to: sink.id, type: RelationTypes.VALIDATES, properties: { partial: true } });
        }
      }
    }
    return edges;
  }

  _classifyParamSource(paramName, content, funcIndex) {
    const ctx = content.substring(Math.max(0, funcIndex - 100), Math.min(content.length, funcIndex + 500));
    if (USER_INPUT_KEYWORDS.some(k => ctx.includes(k))) return ParamSources.USER_INPUT;
    if (ENV_KEYWORDS.some(k => ctx.includes(k))) return ParamSources.ENVIRONMENT;
    if (CONFIG_KEYWORDS.some(k => ctx.includes(k))) return ParamSources.CONFIG;
    return ParamSources.UNTRACKED;
  }

  _extractCallArgs(content, startIdx) {
    let depth = 1, i = startIdx;
    while (i < content.length && depth > 0) {
      if (content[i] === '(') depth++; if (content[i] === ')') depth--;
      if (content[i] === "'" || content[i] === '"' || content[i] === '`') {
        const q = content[i]; i++;
        while (i < content.length && content[i] !== q) { if (content[i] === '\\') i++; i++; }
      }
      i++;
    }
    return content.substring(startIdx, Math.min(i - 1, startIdx + 300)).trim();
  }

  _detectThreatModel(projectPath) {
    const tm = { transport: { type: 'stdio', inheritsEnv: true, localOnly: true, authRequired: false },
      deployment: { mode: 'desktop_app', isProduction: false, autoLoadConfig: false, trustGate: null },
      trustBoundaries: { configSource: 'user_manual', attackerCapabilities: [] } };
    try {
      const pkgPath = path.join(projectPath, 'package.json');
      if (fs.existsSync(pkgPath)) {
        const allCode = this._readAllCodeFiles(projectPath);
        if (/StdioServerTransport|StdioClientTransport/.test(allCode)) tm.transport.type = 'stdio';
        if (/SSEServerTransport|ExpressServer|http\.createServer/.test(allCode)) { tm.transport.type = allCode.includes('StdioServerTransport') ? 'both' : 'http'; tm.transport.localOnly = false; }
        if (/StreamableHTTPServer/.test(allCode)) { tm.transport.type = 'both'; tm.transport.localOnly = false; }
        if (/multitenant|multi.tenant/.test(allCode)) tm.deployment.mode = 'server_multitenant';
        if (/\.mcp\.json|auto.*load|loadConfig.*project/i.test(allCode)) { tm.deployment.autoLoadConfig = true; tm.trustBoundaries.configSource = 'project_file'; }
        if (/fetch.*config|remote.*config/i.test(allCode)) tm.trustBoundaries.configSource = 'remote';
        if (/confirm|prompt.*trust|trust.*prompt|user.*approve/i.test(allCode)) tm.deployment.trustGate = 'prompt';
        if (/--trust-project|trust.*flag/i.test(allCode)) tm.deployment.trustGate = tm.deployment.trustGate ? 'both' : 'flag';
      }
    } catch (e) {}
    return tm;
  }

  _readAllCodeFiles(dir, depth = 0) {
    if (depth > 5) return '';
    let result = '';
    try {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (['node_modules', '.git', 'dist', 'build'].includes(entry.name)) continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) result += this._readAllCodeFiles(full, depth + 1);
        else if (/\.(js|ts|mjs|cjs)$/.test(entry.name)) { try { result += fs.readFileSync(full, 'utf-8') + '\n'; } catch (e) {} }
      }
    } catch (e) {}
    return result;
  }
}

module.exports = { JavaScriptAdapter };
