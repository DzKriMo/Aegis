# KriMo AI - Ultimate Edition

KriMo AI is a powerful autonomous AI agent with cutting-edge capabilities for software engineering, research, and automation.

## Quick Start

```powershell
python krimo_ai\run.py
```

## Core Features

### 1. Multi-Tool System
- **Git Operations**: status, log, diff, branch, checkout, commit, push, pull, merge
- **Docker Management**: list containers, run, stop, exec, logs, build images
- **Database Queries**: SQLite operations with query execution and schema inspection
- **API Client**: HTTP requests (GET, POST, PUT, DELETE) with headers and body
- **Shell Commands**: Execute any CLI command with timeout protection

### 2. Code Interpreter
Execute Python code with sandboxed security:
```bash
/run
print("Hello from the interpreter!")
for i in range(5):
    print(f"Count: {i}")
```

### 3. Multi-Agent Orchestration
Create and coordinate multiple AI agents:
- **Roles**: Planner, Coder, Researcher, Reviewer, Executor, Coordinator
- **Parallel execution** of independent tasks
- **Team collaboration** for complex workflows

### 4. Persistent Memory
Semantic memory with search and recall:
- Store facts, preferences, and knowledge
- Query by semantic similarity
- Persistent across sessions

### 5. Vision Capabilities
- **Image Analysis**: Analyze images using vision models
- **OCR**: Extract text from images
- **Screenshot**: Capture and analyze screen content

### 6. Autonomous Execution
Self-planning and self-correcting agent:
- Automatic task decomposition
- Self-correction on failures
- Multi-step execution loops

### 7. Document Processing
Read and write various document formats:
- **PDF**: Extract text and metadata
- **Word (.docx)**: Read and create documents
- **Excel (.xlsx)**: Read spreadsheet data
- **CSV/JSON**: Parse structured data

### 8. Enhanced Planning
- Task decomposition with dependencies
- Risk identification
- Time estimation
- Plan optimization

## Commands

### File & Code Operations
```
/autocode <task>     Multi-step coding with tool use
/run [lang]          Execute code (python, js, shell)
/doc read <path>    Read document
/doc write <path>    Write document
```

### Tool Execution
```
/tool git status                    Git operations
/tool docker ps                     Container management
/tool database execute "SELECT *"   SQL queries
/tool shell ls -la                  Shell commands
```

### Autonomous Mode
```
/autonomous Build a web scraper for news articles
/autonomous Fix all bugs in the test suite
```

### Vision & Documents
```
/vision analyze image.png
/vision screenshot
/vision ocr document.jpg
```

### Multi-Agent
```
/agent create MyCoder coder
/agent list
/agent run <agent_id> <task>
```

### Memory
```
/mem remember Important: Project deadline is Friday
/mem recall project deadline
/mem stats
/mem clear
```

### Planning
```
/plan Create a REST API for user management
```

### Session Management
```
/new              New session
/attach <id>      Attach to session
/risk             Check risk level
/resetrisk        Reset risk score
/model            Show model info
/help             Show all commands
```

## Environment Variables

```bash
AEGIS_BASE_URL=http://127.0.0.1:8000/v1
AEGIS_API_KEY=your_key
AGENT_MODEL_ENDPOINT=http://127.0.0.1:11434/v1/chat/completions
AGENT_MODEL_NAME=qwen2.5:7b-instruct
AGENT_MODEL_TEMPERATURE=0.1
AGENT_MODEL_MAX_TOKENS=400
AGENT_MODEL_STREAM=true
```

## Dependencies

Install optional dependencies for enhanced capabilities:
```powershell
pip install pillow pytesseract pypdf python-docx openpyxl pandas matplotlib
```

For OCR: Install Tesseract OCR engine
For Vision: Run Ollama with llava model

## Architecture

```
krimo_ai/src/krimo_ai/
├── __init__.py
├── config.py          # Configuration
├── cli.py             # Command-line interface
├── main.py            # Entry point
├── memory.py          # Session memory
├── modeling.py         # LLM integration
├── rendering.py        # Output formatting
├── runtime.py         # Aegis runtime
├── actions.py         # Tool parsing
├── tools.py           # Enhanced tool system
├── interpreter.py     # Code execution
├── multiagent.py      # Multi-agent system
├── persistent_memory.py # Semantic memory
├── vision.py          # Image analysis
├── documents.py       # Document processing
└── autonomous.py      # Self-planning agent
```

## Examples

### Build and Deploy
```
you> /autonomous Deploy my app to Docker and run tests
```

### Research Task
```
you> /autonomous Find all security vulnerabilities in this codebase
```

### Data Analysis
```
you> /run python
import pandas as pd
df = pd.read_csv('data.csv')
print(df.describe())
```

### Multi-Agent Team
```
you> /agent create coordinator coordinator
you> /agent create coder coder
you> /agent create reviewer reviewer
```
