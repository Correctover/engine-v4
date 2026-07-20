// semantic/adapters/python.js
const fs = require('fs');
const path = require('path');
const { EntityTypes, RelationTypes, ParamSources, SinkSeverity, EntityCategories, SchemaVersion } = require('../schema');

const PY_DANGER_SINKS = {
  'open': { type: EntityTypes.FILE_OPERATION.value, op: 'read/write', severity: SinkSeverity.MEDIUM.level },
  'os.remove': { type: EntityTypes.FILE_OPERATION.value, op: 'delete', severity: SinkSeverity.HIGH.level },
  'os.unlink': { type: EntityTypes.FILE_OPERATION.value, op: 'delete', severity: SinkSeverity.HIGH.level },
  'os.rename': { type: EntityTypes.FILE_OPERATION.value, op: 'write', severity: SinkSeverity.HIGH.level },
  'shutil.copy': { type: EntityTypes.FILE_OPERATION.value, op: 'write', severity: SinkSeverity.HIGH.level },
  'shutil.copy2': { type: EntityTypes.FILE_OPERATION.value, op: 'write', severity: SinkSeverity.HIGH.level },
  'shutil.move': { type: EntityTypes.FILE_OPERATION.value, op: 'write', severity: SinkSeverity.HIGH.level },
  'shutil.rmtree': { type: EntityTypes.FILE_OPERATION.value, op: 'delete', severity: SinkSeverity.HIGH.level },
  'pathlib.Path.read_text': { type: EntityTypes.FILE_OPERATION.value, op: 'read', severity: SinkSeverity.MEDIUM.level },
  'pathlib.Path.write_text': { type: EntityTypes.FILE_OPERATION.value, op: 'write', severity: SinkSeverity.HIGH.level },
  'pathlib.Path.unlink': { type: EntityTypes.FILE_OPERATION.value, op: 'delete', severity: SinkSeverity.HIGH.level },
  'os.system': { type: EntityTypes.EXEC_SINK.value, op: 'system', severity: SinkSeverity.CRITICAL.level },
  'os.popen': { type: EntityTypes.EXEC_SINK.value, op: 'popen', severity: SinkSeverity.CRITICAL.level },
  'subprocess.run': { type: EntityTypes.EXEC_SINK.value, op: 'run', severity: SinkSeverity.CRITICAL.level },
  'subprocess.call': { type: EntityTypes.EXEC_SINK.value, op: 'call', severity: SinkSeverity.CRITICAL.level },
  'subprocess.check_output': { type: EntityTypes.EXEC_SINK.value, op: 'check_output', severity: SinkSeverity.CRITICAL.level },
  'subprocess.Popen': { type: EntityTypes.EXEC_SINK.value, op: 'Popen', severity: SinkSeverity.CRITICAL.level },
  'subprocess.check_call': { type: EntityTypes.EXEC_SINK.value, op: 'check_call', severity: SinkSeverity.CRITICAL.level },
  'eval': { type: EntityTypes.EVAL_SINK.value, op: 'eval', severity: SinkSeverity.CRITICAL.level },
  'exec': { type: EntityTypes.EVAL_SINK.value, op: 'exec', severity: SinkSeverity.CRITICAL.level },
  'compile': { type: EntityTypes.EVAL_SINK.value, op: 'compile', severity: SinkSeverity.CRITICAL.level },
  '__import__': { type: EntityTypes.EVAL_SINK.value, op: 'import', severity: SinkSeverity.CRITICAL.level },
  'importlib.import_module': { type: EntityTypes.EVAL_SINK.value, op: 'import', severity: SinkSeverity.CRITICAL.level },
  'requests.get': { type: EntityTypes.NETWORK_REQUEST.value, op: 'get', severity: SinkSeverity.HIGH.level },
  'requests.post': { type: EntityTypes.NETWORK_REQUEST.value, op: 'post', severity: SinkSeverity.HIGH.level },
  'requests.put': { type: EntityTypes.NETWORK_REQUEST.value, op: 'put', severity: SinkSeverity.HIGH.level },
  'requests.delete': { type: EntityTypes.NETWORK_REQUEST.value, op: 'delete', severity: SinkSeverity.HIGH.level },
  'requests.request': { type: EntityTypes.NETWORK_REQUEST.value, op: 'request', severity: SinkSeverity.HIGH.level },
  'urllib.request.urlopen': { type: EntityTypes.NETWORK_REQUEST.value, op: 'urlopen', severity: SinkSeverity.HIGH.level },
  'httpx.get': { type: EntityTypes.NETWORK_REQUEST.value, op: 'get', severity: SinkSeverity.HIGH.level },
  'httpx.post': { type: EntityTypes.NETWORK_REQUEST.value, op: 'post', severity: SinkSeverity.HIGH.level },
  'httpx.AsyncClient': { type: EntityTypes.NETWORK_REQUEST.value, op: 'request', severity: SinkSeverity.HIGH.level },
  'aiohttp.ClientSession': { type: EntityTypes.NETWORK_REQUEST.value, op: 'request', severity: SinkSeverity.HIGH.level },
  'print': { type: EntityTypes.LOG_OUTPUT.value, op: 'print', severity: SinkSeverity.LOW.level },
  'logging.info': { type: EntityTypes.LOG_OUTPUT.value, op: 'info', severity: SinkSeverity.LOW.level },
  'logging.debug': { type: EntityTypes.LOG_OUTPUT.value, op: 'debug', severity: SinkSeverity.LOW.level },
  'logging.warning': { type: EntityTypes.LOG_OUTPUT.value, op: 'warning', severity: SinkSeverity.LOW.level },
  'logging.error': { type: EntityTypes.LOG_OUTPUT.value, op: 'error', severity: SinkSeverity.LOW.level },
  'sys.stdout.write': { type: EntityTypes.LOG_OUTPUT.value, op: 'write', severity: SinkSeverity.LOW.level },
};

const PY_VALIDATION_FNS = [
  'os.path.exists', 'os.path.isfile', 'os.path.isdir',
  'os.path.abspath', 'os.path.realpath', 'os.path.normpath',
  'pathlib.Path.resolve', 'pathlib.Path.absolute',
  'urllib.parse.urlparse', 'urllib.parse.urljoin',
  'ipaddress.ip_address', 'ipaddress.ip_network',
  're.match', 're.fullmatch', 're.search',
  'isinstance', 'type(',
  'validate', 'sanitize', 'escape', 'clean',
  'werkzeug.utils.secure_filename',
];

const PY_MCP_PATTERNS = {
  server_decorators: [/@(?:mcp|server|app)\.tool\s*\(/, /@(?:mcp|server|app)\.resource\s*\(/, /@(?:mcp|server|app)\.prompt\s*\(/, /@server\.list_tools/, /@server\.call_tool/],
  client_patterns: [/(?:ClientSession|StdioServerParameters|mcp_client|MCPClient)/, /(?:streamablehttp_client|sse_client|stdio_client)/, /(?:from\s+mcp\s+import|import\s+mcp)/, /(?:connect_to_server|create_session)/],
  config_patterns: [/(?:mcp_config|MCPConfig|server_config|MCP_SERVERS)/, /(?:HttpMCPConfig|StdioMCPConfig|SSEConfig)/, /(?:url|endpoint|command|args)\s*[=:]\s*/],
  class_def: /class\s+(\w+)\s*(?:\([^)]*\))?\s*:/,
  func_def: /(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)/,
  env_access: /(?:os\.environ|os\.getenv|environ\[)\s*[\[\(]?\s*["']?(\w+)/,
  import_stmt: /(?:from\s+([\w.]+)\s+import\s+([\w.*, ]+)|import\s+([\w., ]+))/,
};

class PythonAdapter {
  constructor() { this.sinks = PY_DANGER_SINKS; this.validators = PY_VALIDATION_FNS; }

  extract(projectPath, meta = {}) {
    const files = this._collectPythonFiles(projectPath);
    const entities = [];
    const relations = [];
    let entityIdCounter = 0;

    for (const filePath of files) {
      const relPath = path.relative(projectPath, filePath);
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');
      const isMcpFile = this._isMcpRelated(content);
      if (!isMcpFile && files.length > 10) continue;

      const fileContext = { filePath: relPath, lines, content, isMcpFile };

      const mcpE = this._extractMcpEntities(fileContext, entityIdCounter);
      entities.push(...mcpE.entities); relations.push(...mcpE.relations);
      entityIdCounter += mcpE.entities.length;

      const sinkE = this._extractSinkEntities(fileContext, entityIdCounter);
      entities.push(...sinkE.entities); relations.push(...sinkE.relations);
      entityIdCounter += sinkE.entities.length;

      const valE = this._extractValidationEntities(fileContext, entityIdCounter);
      entities.push(...valE.entities); relations.push(...valE.relations);
      entityIdCounter += valE.entities.length;

      const cfgE = this._extractConfigEntities(fileContext, entityIdCounter);
      entities.push(...cfgE.entities); relations.push(...cfgE.relations);
      entityIdCounter += cfgE.entities.length;

      const flowRels = this._buildDataflowRelations(entities, relations, fileContext);
      relations.push(...flowRels);
    }

    return {
      _schemaVersion: { major: 4, minor: 0, patch: 0 },
      project: meta.name || path.basename(projectPath),
      language: 'python',
      extractedAt: new Date().toISOString(),
      threatModel: meta.threatModel || null,
      entities, relations,
      metadata: { total_files: files.length, scanned_files: files.length,
        mcp_related_files: files.filter(f => this._isMcpRelated(fs.readFileSync(f, 'utf-8'))).length },
    };
  }

  _collectPythonFiles(projectPath) {
    const pyFiles = [];
    const skipDirs = new Set(['__pycache__', '.git', 'node_modules', '.venv', 'venv', 'env', '.tox', '.mypy_cache', 'dist', 'build', '.eggs']);
    function walk(dir) {
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const entry of entries) {
        if (skipDirs.has(entry.name)) continue;
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(fullPath);
        else if (entry.isFile() && entry.name.endsWith('.py')) pyFiles.push(fullPath);
      }
    }
    walk(projectPath);
    return pyFiles;
  }

  _isMcpRelated(content) {
    const allPatterns = [...PY_MCP_PATTERNS.server_decorators, ...PY_MCP_PATTERNS.client_patterns, ...PY_MCP_PATTERNS.config_patterns];
    return allPatterns.some(p => p.test(content));
  }

  _extractMcpEntities(ctx, startId) {
    const entities = []; const relations = [];
    const { lines, filePath } = ctx;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of PY_MCP_PATTERNS.server_decorators) {
        if (pattern.test(line)) {
          let funcLine = i + 1;
          while (funcLine < lines.length && !PY_MCP_PATTERNS.func_def.test(lines[funcLine])) { funcLine++; if (funcLine > i + 5) break; }
          if (funcLine < lines.length) {
            const match = lines[funcLine].match(PY_MCP_PATTERNS.func_def);
            if (match) {
              const id = `py_mcp_tool_${startId + entities.length}`;
              entities.push({ id, type: EntityTypes.MCP_TOOL_HANDLER.value, name: match[1],
                location: { file: filePath, line: funcLine + 1, column: 0, sourceMapAvailable: false },
                properties: { category: EntityCategories.ABSTRACT, params: this._extractPythonParams(match[2]),
                  mcpDecorator: line.trim(), isAsync: lines[funcLine].includes('async def') } });
            }
          }
          break;
        }
      }
      for (const pattern of PY_MCP_PATTERNS.client_patterns) {
        if (pattern.test(line)) {
          const id = `py_mcp_client_${startId + entities.length}`;
          entities.push({ id, type: EntityTypes.MCP_CLIENT.value, name: line.match(/\w+/)?.[0] || 'mcp_client',
            location: { file: filePath, line: i + 1, column: line.search(/\S/), sourceMapAvailable: false },
            properties: { category: EntityCategories.ABSTRACT, clientType: line.includes('Session') ? 'session' : 'transport' } });
          break;
        }
      }
      for (const pattern of PY_MCP_PATTERNS.config_patterns) {
        if (pattern.test(line)) {
          const id = `py_mcp_config_${startId + entities.length}`;
          entities.push({ id, type: EntityTypes.CONFIG_FIELD.value, name: line.match(/(\w+)\s*[=:]/)?.[1] || 'mcp_config',
            location: { file: filePath, line: i + 1, column: line.search(/\S/), sourceMapAvailable: false },
            properties: { category: EntityCategories.META, source: ParamSources.CONFIG } });
          break;
        }
      }
    }
    return { entities, relations };
  }

  _extractSinkEntities(ctx, startId) {
    const entities = []; const relations = [];
    const { lines, filePath } = ctx;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]; const stripped = line.trim();
      if (stripped.startsWith('#') || !stripped) continue;
      for (const [fnName, sinkInfo] of Object.entries(this.sinks)) {
        const callPattern = new RegExp(`(?:^|[\\s=,(])${fnName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\(`);
        if (callPattern.test(line)) {
          const id = `py_sink_${startId + entities.length}`;
          entities.push({ id, type: typeof sinkInfo.type === 'string' ? sinkInfo.type : sinkInfo.type.value,
            name: fnName,
            location: { file: filePath, line: i + 1, column: line.search(/\S/), sourceMapAvailable: false },
            properties: { category: EntityCategories.CONCRETE, operation: sinkInfo.op, severity: sinkInfo.severity } });
          break;
        }
      }
    }
    return { entities, relations };
  }

  _extractValidationEntities(ctx, startId) {
    const entities = []; const relations = [];
    const { lines, filePath } = ctx;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const valFn of this.validators) {
        if (line.includes(valFn)) {
          const id = `py_val_${startId + entities.length}`;
          entities.push({ id, type: EntityTypes.VALIDATION_GATE.value, name: valFn,
            location: { file: filePath, line: i + 1, column: line.search(/\S/), sourceMapAvailable: false },
            properties: { category: EntityCategories.CONCRETE, validationType: this._inferValidationType(valFn), onFailure: 'block' } });
          break;
        }
      }
    }
    return { entities, relations };
  }

  _extractConfigEntities(ctx, startId) {
    const entities = []; const relations = [];
    const { lines, filePath } = ctx;
    for (let i = 0; i < lines.length; i++) {
      const match = lines[i].match(PY_MCP_PATTERNS.env_access);
      if (match) {
        const envVar = match[1];
        const id = `py_env_${startId + entities.length}`;
        const isSensitive = /^(AWS_|SECRET_|TOKEN_|API_|KEY_|PASSWORD_|DB_|DATABASE_|OPENAI_|ANTHROPIC_|GITHUB_)/.test(envVar);
        entities.push({ id, type: EntityTypes.CONFIG_FIELD.value, name: envVar,
          location: { file: filePath, line: i + 1, column: lines[i].search(/\S/), sourceMapAvailable: false },
          properties: { category: EntityCategories.META, source: ParamSources.ENVIRONMENT, trust: isSensitive ? 0.8 : 0.6, sensitive: isSensitive } });
      }
    }
    return { entities, relations };
  }

  _buildDataflowRelations(allEntities, existingRelations, ctx) {
    const relations = [];
    const { filePath } = ctx;
    const fileEntities = allEntities.filter(e => e.location?.file === filePath);
    const toolHandlers = fileEntities.filter(e => e.type === EntityTypes.MCP_TOOL_HANDLER.value);
    const sinks = fileEntities.filter(e => [EntityTypes.EXEC_SINK.value, EntityTypes.EVAL_SINK.value, EntityTypes.FILE_OPERATION.value, EntityTypes.NETWORK_REQUEST.value].includes(e.type));
    const validators = fileEntities.filter(e => e.type === EntityTypes.VALIDATION_GATE.value);

    for (const handler of toolHandlers) {
      for (const sink of sinks) {
        if (sink.location.line > handler.location.line) {
          const hasValidator = validators.some(v => v.location.line > handler.location.line && v.location.line < sink.location.line);
          relations.push({ from: handler.id, to: sink.id, type: RelationTypes.FLOWS_INTO,
            properties: { validated: hasValidator, sanitized: false, taintMode: 'exact', paramSource: ParamSources.USER_INPUT } });
        }
      }
    }

    const configs = fileEntities.filter(e => e.type === EntityTypes.CONFIG_FIELD.value);
    const clients = fileEntities.filter(e => e.type === EntityTypes.MCP_CLIENT.value);
    for (const config of configs) {
      for (const client of clients) {
        if (client.location.line > config.location.line) {
          relations.push({ from: config.id, to: client.id, type: RelationTypes.CONFIGURES, properties: { direct: true } });
        }
      }
      for (const sink of sinks) {
        if (sink.location.line > config.location.line) {
          relations.push({ from: config.id, to: sink.id, type: RelationTypes.FLOWS_INTO,
            properties: { validated: false, sanitized: false, taintMode: 'exact', paramSource: config.properties.source } });
        }
      }
    }
    return relations;
  }

  _extractPythonParams(paramStr) {
    if (!paramStr) return [];
    return paramStr.split(',').map(p => p.trim().split(':')[0].split('=')[0].trim()).filter(p => p && p !== 'self' && p !== 'cls');
  }

  _inferValidationType(fnName) {
    if (fnName.includes('path') || fnName.includes('realpath') || fnName.includes('normpath') || fnName.includes('resolve')) return 'path_validation';
    if (fnName.includes('url') || fnName.includes('urlparse')) return 'url_validation';
    if (fnName.includes('re.match') || fnName.includes('re.fullmatch')) return 'regex_validation';
    if (fnName.includes('isinstance') || fnName.includes('type(')) return 'type_check';
    if (fnName.includes('ip_address') || fnName.includes('ip_network')) return 'ip_validation';
    if (fnName.includes('secure_filename')) return 'filename_sanitization';
    if (fnName.includes('escape') || fnName.includes('sanitize')) return 'content_sanitization';
    return 'generic_validation';
  }
}

module.exports = { PythonAdapter };
