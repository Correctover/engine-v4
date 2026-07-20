# Correctover Engine v4

Semantic pattern matching for MCP security audit. 89/89 tests passing.

## Quick Start
```bash
node cli.js scan /path/to/project
node test_all.js  
```

## Architecture
- semantic/ - Schema v4.0 + Python/JS adapters  
- matching/ - Pattern matcher + confidence scoring  
- patterns/ - 9 patterns (5 generic + 4 AgentScope seeds)  
- migration/ - Migration tracking  

License: MIT
