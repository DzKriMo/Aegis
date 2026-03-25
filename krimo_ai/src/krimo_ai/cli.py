from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Optional

import requests

from .actions import detect_direct_tool_intent, parse_agent_action
from .config import AEGIS_API_KEY, AEGIS_BASE, AGENT_BANNER, AGENT_NAME, MODEL_ENDPOINT, MODEL_NAME, MODEL_STREAM_ENABLED
from .memory import AgentMemory
from .modeling import force_plain_answer, model_chat
from .rendering import format_display_text
from .runtime import attach_runtime, build_memory_context, create_runtime, execute_agent_tool_action, guard_output_with_approvals, maybe_sensitive_input_notice, normalize_action_payload, run_autocode_task
from .vision import OCR_AVAILABLE, PIL_AVAILABLE

from aegis.tools.client import AegisClient
from aegis.services.browser_session import browser_available


def _capability_status() -> str:
    browser_ok, browser_err = browser_available()
    browser_label = "browser=ready" if browser_ok else f"browser=missing ({browser_err or 'unavailable'})"
    ocr_label = "ocr=ready" if PIL_AVAILABLE and OCR_AVAILABLE else "ocr=missing"
    vision_label = "vision=ready" if PIL_AVAILABLE else "vision=missing"
    return f"[capabilities] {browser_label} • {vision_label} • {ocr_label}"


def print_banner(session_id: str) -> None:
    print(AGENT_BANNER)
    print(f"{AGENT_NAME} is ready (Ultimate Edition)")
    print(f"[aegis] session={session_id}")
    print("[status] Enhanced: git, docker, database, interpreter, vision, autonomous, documents")
    print(_capability_status())


def execute_tool_command(command: str, args: str) -> str:
    from .tools import get_tool, execute_tool
    parts = args.split(None, 1)
    if not parts:
        return "Usage: /tool <name> <method> [args_json]"

    tool_name = parts[0]
    method = parts[1] if len(parts) > 1 else "execute"
    tool_args = {}

    if len(parts) > 2:
        try:
            tool_args = json.loads(parts[2])
        except json.JSONDecodeError:
            return f"Invalid JSON: {parts[2]}"

    tool = get_tool(tool_name)
    if not tool:
        return f"Unknown tool: {tool_name}. Available: shell, git, docker, database, api_client, file_search"

    result = execute_tool(tool_name, method, tool_args)
    return json.dumps(result.to_dict(), indent=2)


def execute_code_command(code: str, language: str = "python") -> str:
    from .interpreter import CodeInterpreter
    interpreter = CodeInterpreter(sandbox=True)
    result = interpreter.run(code, language)
    output = result.output
    if result.error:
        output += f"\n[Error] {result.error}"
    output += f"\n[Execution time: {result.execution_time:.2f}s]"
    return output


def execute_autonomous_command(task: str, steps: int = 10) -> str:
    from .autonomous import AutonomousController
    from .tools import execute_tool

    def model_func(messages):
        return model_chat(messages)

    def exec_func(tool_name, args):
        result = execute_tool(tool_name, "execute", args)
        return result.to_dict() if hasattr(result, 'to_dict') else str(result)

    controller = AutonomousController(
        model_func=model_func,
        execute_func=exec_func,
        max_iterations=steps,
    )

    planned_task = controller.plan_task(task)
    result = controller.execute_task(planned_task)

    if result.get("success"):
        return f"[Autonomous completed in {result.get('duration', 0):.2f}s]\nSteps executed: {len(result.get('results', []))}"
    return f"[Autonomous failed]: {result.get('error', 'Unknown error')}"


def execute_vision_command(args: str) -> str:
    from .vision import VisionCapabilities
    parts = args.split(None, 1)
    if not parts:
        return "Usage: /vision <command> [args]\nCommands: analyze <path>, screenshot, ocr <path>"

    cmd = parts[0]
    vision = VisionCapabilities()

    if cmd == "analyze" and len(parts) > 1:
        result = vision.analyze_image_file(parts[1])
        return result.description if result.success else f"Error: {result.error}"

    if cmd == "screenshot":
        result = vision.analyze_screenshot()
        return result.description if result.success else f"Error: {result.error}"

    if cmd == "ocr" and len(parts) > 1:
        result = vision.extract_text_from_image(parts[1])
        return result.text if result.success else f"Error: {result.error}"

    return f"Unknown vision command: {cmd}"


def execute_doc_command(args: str) -> str:
    from .documents import DocumentProcessor
    parts = args.split(None, 2)
    if len(parts) < 2:
        return "Usage: /doc <read|write> <path> [content]"

    cmd = parts[0]
    path = parts[1]
    processor = DocumentProcessor()

    if cmd == "read":
        result = processor.read(path)
        return result.content[:2000] + ("..." if len(result.content) > 2000 else "") if result.success else f"Error: {result.error}"

    if cmd == "write" and len(parts) > 2:
        result = processor.write(path, parts[2])
        return "Document written successfully" if result.success else f"Error: {result.error}"

    return f"Unknown doc command: {cmd}"


def execute_agent_command(args: str) -> str:
    from .multiagent import MultiAgentOrchestrator, AgentRole

    parts = args.split(None, 2)
    if not parts:
        return "Usage: /agent <create|list|run|task> [args]"

    cmd = parts[0]

    if cmd == "create" and len(parts) > 2:
        name = parts[1]
        role_str = parts[2] if len(parts) > 2 else "specialist"
        try:
            role = AgentRole(role_str)
        except ValueError:
            role = AgentRole.SPECIALIST

        orchestrator = MultiAgentOrchestrator(model_func=model_chat)
        agent_id = orchestrator.create_agent(
            name=name,
            role=role,
            description=f"Agent: {name}",
        )
        return f"Created agent {name} with ID: {agent_id}"

    if cmd == "list":
        orchestrator = MultiAgentOrchestrator(model_func=model_chat)
        status = orchestrator.get_status()
        return json.dumps(status, indent=2)

    return f"Unknown agent command: {cmd}"


def execute_plan_command(task: str) -> str:
    from .autonomous import EnhancedPlanner
    planner = EnhancedPlanner(model_func=model_chat)
    plan = planner.create_plan(task)
    return json.dumps(plan, indent=2)


def execute_memory_command(args: str) -> str:
    from .persistent_memory import PersistentAgentMemory
    parts = args.split(None, 1)
    if not parts:
        return "Usage: /memory <remember|recall|stats|clear> [args]"

    cmd = parts[0]
    pmem = PersistentAgentMemory()

    if cmd == "remember" and len(parts) > 1:
        memory_id = pmem.remember(parts[1])
        return f"Remembered with ID: {memory_id}"

    if cmd == "recall" and len(parts) > 1:
        memories = pmem.recall(parts[1])
        if memories:
            return "\n".join(f"- {m}" for m in memories)
        return "No memories found"

    if cmd == "stats":
        stats = pmem.get_stats()
        return json.dumps(stats, indent=2)

    if cmd == "clear":
        count = pmem.clear_memory()
        return f"Cleared {count} memories"

    return f"Unknown memory command: {cmd}"


def execute_do_command(task: str) -> str:
    from .autonomous_engine import create_engine, ToolRegistry

    tools = {
        "shell": lambda command, **kw: __import__("subprocess").run(command, shell=True, capture_output=True, text=True).stdout.decode(),
        "read_file": lambda path, **kw: open(path, "r").read() if __import__("os").path.exists(path) else "File not found",
        "write_file": lambda path, content, **kw: (open(path, "w").write(content) or "OK"),
        "list_dir": lambda path, **kw: "\n".join(__import__("os").listdir(path or ".")),
    }

    engine = create_engine(model_func=model_chat, verbose=True)
    for name, func in tools.items():
        engine.register_tool(name, func, f"{name} operation")

    print(f"[*] Planning and executing: {task[:50]}...")
    result = engine.run(task)

    if result.get("success"):
        steps = result.get("completed_steps", 0)
        duration = result.get("duration", 0)
        return f"[+] Completed {steps} steps in {duration:.2f}s"
    return f"[!] Failed: {result.get('error', 'Unknown error')}"


def execute_watch_command(args: str) -> str:
    from .file_watcher import DirectoryMonitor, EventType
    parts = args.split(None, 1)
    if not parts:
        return "Usage: /watch <start|stop|status|events> [path]"

    cmd = parts[0]
    path = parts[1] if len(parts) > 1 else "."

    global _file_monitor
    if not hasattr(sys.modules[__name__], '_file_monitor'):
        from .file_watcher import DirectoryMonitor
        globals()['_file_monitor'] = DirectoryMonitor()

    monitor = globals()['_file_monitor']

    if cmd == "start":
        watch_id = monitor.watch(path)
        return f"[*] Watching: {watch_id}"

    if cmd == "stop":
        monitor.unwatch(path)
        return f"[*] Stopped watching: {path}"

    if cmd == "status":
        stats = monitor.get_stats()
        return json.dumps(stats, indent=2)

    if cmd == "events":
        events = monitor.get_events(path)
        if not events:
            return "No recent events"
        return "\n".join(f"[{e.event_type.value}] {e.path}" for e in events[-10:])

    return f"Unknown watch command: {cmd}"


def execute_tasks_command(args: str) -> str:
    from .task_queue import JobQueue, JobStatus
    parts = args.split(None, 1)
    if not parts:
        return "Usage: /tasks <list|stats|clear|add> [args]"

    cmd = parts[0]

    global _task_queue
    if not hasattr(sys.modules[__name__], '_task_queue'):
        globals()['_task_queue'] = JobQueue(max_workers=4)
        globals()['_task_queue'].start()

    queue = globals()['_task_queue']

    if cmd == "list":
        jobs = queue.list_jobs(limit=20)
        if not jobs:
            return "No tasks"
        return json.dumps(jobs, indent=2, default=str)

    if cmd == "stats":
        stats = queue.get_stats()
        return json.dumps(stats, indent=2)

    if cmd == "clear":
        queue.clear_completed()
        return "[*] Cleared completed tasks"

    return f"Unknown tasks command: {cmd}"


def execute_context_command(args: str) -> str:
    from .context import ContextManager, ContextType
    parts = args.split(None, 1)
    if not parts:
        return "Usage: /context <add|get|search|stats|export|import> [args]"

    cmd = parts[0]

    global _context_manager
    if not hasattr(sys.modules[__name__], '_context_manager'):
        globals()['_context_manager'] = ContextManager()

    ctx = globals()['_context_manager']

    if cmd == "add" and len(parts) > 1:
        item_id = ctx.add(parts[1], ContextType.MEMORY)
        return f"[*] Added context: {item_id}"

    if cmd == "search" and len(parts) > 1:
        results = ctx.search(parts[1], limit=10)
        if not results:
            return "No results"
        return "\n".join(f"[{r.type.value}] {r.content[:100]}" for r in results)

    if cmd == "stats":
        stats = ctx.get_stats()
        return json.dumps(stats, indent=2)

    if cmd == "export":
        return ctx.export()

    if cmd == "recent":
        recent = ctx.get_recent(limit=10)
        return "\n".join(f"[{r.type.value}] {r.content[:80]}" for r in recent)

    return f"Unknown context command: {cmd}"


import sys


def main() -> int:
    client = AegisClient(AEGIS_BASE, AEGIS_API_KEY)
    session_id, adapter = create_runtime(client)
    memory = AgentMemory()
    print_banner(session_id)
    trusted_local_tools = {
        "filesystem_read", "directory_list", "filesystem_write", "filesystem_edit",
        "filesystem_patch", "file_find", "repo_map", "text_search", "shell",
        "git", "docker", "database", "api_client", "code_interpreter",
    }
    tool_catalog_json = json.dumps(adapter.describe_tools(), indent=2)
    system_prompt = (
        "You are KriMo AI, the ultimate agent with enhanced capabilities. "
        "You can use tools, execute code, manage multiple agents, analyze images, "
        "process documents, and operate autonomously. "
        'Always respond with valid JSON in one of these forms only:\n'
        '{"action":"answer","content":"<final user-facing reply>"}\n'
        '{"action":"tool","tool_name":"<name>","payload":{...}}'
        "\nAvailable guarded tools:\n"
        f"{tool_catalog_json}"
    )
    while True:
        try:
            user_text = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not user_text:
            continue
        lower = user_text.lower()

        if lower in {"exit", "quit"}:
            return 0

        if lower in {"clear", "cls"}:
            os.system("cls" if os.name == "nt" else "clear")
            print_banner(session_id)
            continue

        if lower == "/new":
            session_id, adapter = create_runtime(client)
            memory = AgentMemory()
            print_banner(session_id)
            continue

        if lower.startswith("/attach "):
            target_session = user_text.split(None, 1)[1].strip()
            try:
                client.get_risk(target_session)
            except requests.HTTPError as exc:
                print(f"[agent] could not attach to session {target_session}: {exc}")
                continue
            session_id, adapter = attach_runtime(client, target_session)
            print(f"[aegis] attached session={session_id}")
            continue

        if lower == "/risk":
            risk = client.get_risk(session_id).get("risk_state") or {}
            print("[aegis] " f"quarantined={bool(risk.get('quarantined', False))} " f"cumulative={float(risk.get('cumulative_risk_score', 0.0) or 0.0):.3f}")
            continue

        if lower == "/resetrisk":
            risk = client.reset_risk(session_id).get("risk_state") or {}
            print("[aegis] risk reset " f"quarantined={bool(risk.get('quarantined', False))} " f"cumulative={float(risk.get('cumulative_risk_score', 0.0) or 0.0):.3f}")
            continue

        if lower == "/session":
            print(f"[aegis] session={session_id}")
            continue

        if lower == "/model":
            print(f"[aegis] model={MODEL_NAME} endpoint={MODEL_ENDPOINT}")
            continue

        if lower == "/memory":
            print(memory.render())
            continue

        if lower.startswith("/remember "):
            memory.remember_note(user_text.split(None, 1)[1])
            print("[aegis] memory updated")
            continue

        if lower.startswith("/autocode "):
            task = user_text.split(None, 1)[1].strip()
            guarded_in = adapter.guard_input(task, metadata={"source": "krimo_ai", "mode": "autocode"})
            if guarded_in.get("blocked"):
                print(f"aegis(block)> {guarded_in.get('message')}")
                continue
            final_output = run_autocode_task(guarded_in.get("sanitized_content") or task, adapter, client, session_id, tool_catalog_json, memory, trusted_local_tools)
            guarded_out = guard_output_with_approvals(adapter, client, session_id, final_output, {"source": "krimo_ai", "mode": "autocode"})
            print(f"{AGENT_NAME}> {format_display_text(guarded_out.get('sanitized_output') or final_output)}")
            continue

        if lower.startswith("/tool "):
            args_str = user_text[6:].strip()
            print(f"{AGENT_NAME}> {execute_tool_command('tool', args_str)}")
            continue

        if lower.startswith("/run "):
            code_block = user_text[5:].strip()
            lang = "python"
            if code_block.startswith("```"):
                lines = code_block.split("\n")
                if lines[0].strip("`").strip():
                    lang = lines[0].strip("`").strip()
                code_block = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
            print(f"{AGENT_NAME}> {execute_code_command(code_block, lang)}")
            continue

        if lower.startswith("/autonomous "):
            task = user_text[12:].strip()
            print(f"{AGENT_NAME}> Planning and executing: {task[:50]}...")
            print(f"{AGENT_NAME}> {execute_autonomous_command(task)}")
            continue

        if lower.startswith("/vision "):
            args_str = user_text[8:].strip()
            print(f"{AGENT_NAME}> {execute_vision_command(args_str)}")
            continue

        if lower.startswith("/doc "):
            args_str = user_text[5:].strip()
            print(f"{AGENT_NAME}> {execute_doc_command(args_str)}")
            continue

        if lower.startswith("/agent "):
            args_str = user_text[7:].strip()
            print(f"{AGENT_NAME}> {execute_agent_command(args_str)}")
            continue

        if lower.startswith("/plan "):
            task = user_text[6:].strip()
            print(f"{AGENT_NAME}> {execute_plan_command(task)}")
            continue

        if lower.startswith("/mem "):
            args_str = user_text[5:].strip()
            print(f"{AGENT_NAME}> {execute_memory_command(args_str)}")
            continue

        if lower.startswith("/do "):
            task = user_text[4:].strip()
            print(f"{AGENT_NAME}> {execute_do_command(task)}")
            continue

        if lower.startswith("/watch "):
            args_str = user_text[7:].strip()
            print(f"{AGENT_NAME}> {execute_watch_command(args_str)}")
            continue

        if lower.startswith("/tasks "):
            args_str = user_text[7:].strip()
            print(f"{AGENT_NAME}> {execute_tasks_command(args_str)}")
            continue

        if lower.startswith("/context "):
            args_str = user_text[9:].strip()
            print(f"{AGENT_NAME}> {execute_context_command(args_str)}")
            continue

        if lower == "/help":
            print("""
KriMo AI Ultimate - Commands:
  /new                    - Start new session
  /attach <id>           - Attach to session
  /do <task>             - Execute task with tool planning
  /autocode <task>        - Multi-step coding
  /run [lang] <code>     - Execute code
  /autonomous <task>      - Self-planning execution
  /tool <name> <method>  - Execute tools (git, docker, db, shell)
  /vision analyze <path>  - Analyze image
  /vision screenshot      - Capture screen
  /vision ocr <path>     - Extract text from image
  /doc read <path>        - Read document (PDF, DOCX, XLSX)
  /doc write <path> <txt>- Write document
  /agent create <name>    - Create sub-agent
  /agent list             - List agents
  /plan <task>           - Create execution plan
  /watch start <path>     - Start file watcher
  /watch stop <path>      - Stop file watcher
  /watch status           - Watcher status
  /tasks list             - List queued tasks
  /tasks stats            - Task queue stats
  /context add <text>     - Add to context
  /context search <query> - Search context
  /context recent         - Recent context
  /mem remember <text>    - Store in memory
  /mem recall <query>     - Search memory
  /risk, /resetrisk       - Risk management
  /session, /model        - Info commands
  /memory, /remember       - Session memory
  exit, quit              - Exit
            """)
            continue

        pre_action = detect_direct_tool_intent(user_text, memory.web_results, memory.page_links)
        if pre_action and pre_action.get("action") == "vision_ocr":
            vision_args = "ocr " + str(pre_action.get("path") or "")
            print(f"{AGENT_NAME}> {execute_vision_command(vision_args)}")
            continue
        if pre_action and pre_action.get("action") == "vision_analyze":
            vision_args = "analyze " + str(pre_action.get("path") or "")
            print(f"{AGENT_NAME}> {execute_vision_command(vision_args)}")
            continue
        if pre_action and pre_action.get("action") == "browser_result":
            print(f"{AGENT_NAME}> There is no search result with that number. Run a web search first.")
            continue
        if pre_action and pre_action.get("action") == "browser_link":
            print(f"{AGENT_NAME}> There is no page link with that number. Open a page first.")
            continue
        guard_text = str(pre_action.get("guard_text") or user_text) if pre_action else user_text
        guarded_in = adapter.guard_input(guard_text, metadata={"source": "krimo_ai", "fast_path": bool(pre_action)})
        if guarded_in.get("blocked"):
            print(f"aegis(block)> {guarded_in.get('message')}")
            continue
        sensitive_notice = maybe_sensitive_input_notice(guard_text, guarded_in)
        if sensitive_notice:
            guarded_out = guard_output_with_approvals(adapter, client, session_id, sensitive_notice, {"source": "krimo_ai", "soft_reply": "pii_redaction"})
            print(f"{AGENT_NAME}> {format_display_text(guarded_out.get('sanitized_output') or sensitive_notice)}")
            continue
        safe_input = guarded_in.get("sanitized_content") or guard_text
        action = pre_action or detect_direct_tool_intent(safe_input, memory.web_results, memory.page_links)
        if action is None:
            messages = [{"role": "system", "content": system_prompt + build_memory_context(memory)}, {"role": "user", "content": safe_input}]
            first = model_chat(messages, stream=MODEL_STREAM_ENABLED, stream_label="Planning response")
            action = normalize_action_payload(parse_agent_action(first))
            if action.get("action") == "answer" and not str(action.get("content") or "").strip() and first.strip().startswith("{"):
                action = {"action": "answer", "content": force_plain_answer(safe_input)}
        else:
            print(f"[agent] fast_path={action.get('tool_name', 'answer')}")
        action = normalize_action_payload(action)
        final_output = action.get("content") or ""
        output_metadata: Dict[str, Any] = {"source": "krimo_ai"}
        if action.get("action") == "tool":
            final_output, tool_metadata = execute_agent_tool_action(adapter, client, session_id, action, safe_input, memory, trusted_local_tools)
            output_metadata.update(tool_metadata)
        guarded_out = guard_output_with_approvals(adapter, client, session_id, final_output, output_metadata)
        print(f"{AGENT_NAME}> {format_display_text(guarded_out.get('sanitized_output') or final_output)}")
