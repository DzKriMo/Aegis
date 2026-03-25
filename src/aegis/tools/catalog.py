from __future__ import annotations

from typing import Any, Dict, List


def tool_catalog() -> List[Dict[str, Any]]:
    return [
        {
            "name": "http_fetch",
            "description": "Fetch a URL after Aegis network policy checks.",
            "payload_schema": {"url": "string", "method": "GET|POST|HEAD", "headers": "object?"},
            "use_when": "The agent needs web content from an approved URL.",
        },
        {
            "name": "web_search",
            "description": "Search the public web and return ranked results with titles, URLs, and snippets.",
            "payload_schema": {"query": "string", "max_results": "integer?"},
            "use_when": "The agent needs to discover relevant public pages before opening one.",
        },
        {
            "name": "web_open",
            "description": "Open a web page, extract readable text, and list navigable links.",
            "payload_schema": {"url": "string", "max_links": "integer?"},
            "use_when": "The agent needs to inspect a specific page or follow a previous result/link.",
        },
        {
            "name": "browser_navigate",
            "description": "Navigate a real browser page to a URL with JS-capable rendering.",
            "payload_schema": {"url": "string"},
            "use_when": "A site needs a real browser session instead of simple HTTP fetch/open.",
        },
        {
            "name": "browser_click",
            "description": "Click an element in the current browser page using a CSS selector.",
            "payload_schema": {"selector": "string"},
            "use_when": "The agent needs to follow buttons, tabs, or interactive links in a real page.",
        },
        {
            "name": "browser_type",
            "description": "Type text into an element in the current browser page and optionally submit.",
            "payload_schema": {"selector": "string", "text": "string", "submit": "boolean?"},
            "use_when": "The agent needs to use search boxes, forms, or login-like flows in a controlled browser.",
        },
        {
            "name": "browser_snapshot",
            "description": "Capture a readable snapshot of the current browser page.",
            "payload_schema": {},
            "use_when": "The agent needs the latest page text and links after interactive navigation.",
        },
        {
            "name": "browser_scroll",
            "description": "Scroll the current browser page and capture the updated state.",
            "payload_schema": {"pixels": "integer?"},
            "use_when": "The agent needs to move past the first viewport to reach the next visible section.",
        },
        {
            "name": "browser_screenshot",
            "description": "Capture a screenshot of the current browser page.",
            "payload_schema": {},
            "use_when": "The agent needs a visual artifact or to inspect layout/visual state.",
        },
        {
            "name": "filesystem_read",
            "description": "Read a UTF-8 text file within the allowed root.",
            "payload_schema": {"path": "string"},
            "use_when": "The agent needs existing local file contents.",
        },
        {
            "name": "directory_list",
            "description": "List directory contents within the allowed root.",
            "payload_schema": {"path": "string?"},
            "use_when": "The agent needs to discover available files before reading one.",
        },
        {
            "name": "filesystem_write",
            "description": "Write a UTF-8 text file in dev environments.",
            "payload_schema": {"path": "string", "content": "string", "append": "boolean?"},
            "use_when": "The agent needs to save an artifact or note in a workspace path.",
        },
        {
            "name": "filesystem_edit",
            "description": "Replace exact text inside a UTF-8 file in dev environments.",
            "payload_schema": {"path": "string", "old_text": "string", "new_text": "string", "replace_all": "boolean?"},
            "use_when": "The agent needs a narrow, explicit edit to an existing local file.",
        },
        {
            "name": "filesystem_patch",
            "description": "Apply one or more exact text replacements to a UTF-8 file in dev environments.",
            "payload_schema": {"path": "string", "changes": '[{"old_text":"string","new_text":"string","replace_all":"boolean?"}]'},
            "use_when": "The agent needs to make multiple exact edits in one file safely.",
        },
        {
            "name": "file_find",
            "description": "Find files by glob-like pattern within the allowed root.",
            "payload_schema": {"pattern": "string", "path": "string?", "max_results": "integer?"},
            "use_when": "The agent needs to locate candidate files before reading or editing them.",
        },
        {
            "name": "repo_map",
            "description": "Build a compact repository tree and extension summary within the allowed root.",
            "payload_schema": {"path": "string?", "max_depth": "integer?", "max_entries": "integer?"},
            "use_when": "The agent needs a quick structural map of the workspace or a subtree.",
        },
        {
            "name": "text_search",
            "description": "Search recursively for text in files within the allowed root.",
            "payload_schema": {"query": "string", "path": "string?", "literal": "boolean?", "case_sensitive": "boolean?", "max_results": "integer?"},
            "use_when": "The agent needs to find code, strings, or references across the workspace.",
        },
        {
            "name": "json_transform",
            "description": "Pretty print, compact, inspect keys, or derive a simple schema from JSON-like data.",
            "payload_schema": {"data": "any", "operation": "pretty|compact|keys|schema"},
            "use_when": "The agent needs to cleanly inspect or reshape structured data.",
        },
        {
            "name": "shell",
            "description": "Run an allowlisted local command in dev only.",
            "payload_schema": {"command": "string"},
            "use_when": "The agent needs a narrow local command and no safer structured tool fits.",
        },
    ]
