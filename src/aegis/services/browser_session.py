from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
import os
import re


_PLAYWRIGHT_ERR: Optional[str] = None

try:
    from playwright.sync_api import sync_playwright  # type: ignore
except Exception as exc:  # pragma: no cover - dependency is optional
    sync_playwright = None  # type: ignore
    _PLAYWRIGHT_ERR = str(exc)


@dataclass
class _BrowserState:
    playwright: Any
    browser: Any
    context: Any
    page: Any


_BROWSER_SESSIONS: Dict[str, _BrowserState] = {}


def browser_available() -> tuple[bool, Optional[str]]:
    if sync_playwright is None:
        return False, _PLAYWRIGHT_ERR or "playwright_not_available"
    return True, None


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    return cleaned[:80] or "browser"


def _ensure_session(session_id: str) -> _BrowserState:
    current = _BROWSER_SESSIONS.get(session_id)
    if current is not None:
        return current
    if sync_playwright is None:
        raise RuntimeError(_PLAYWRIGHT_ERR or "playwright_not_available")
    pw = sync_playwright().start()
    browser = pw.chromium.launch(headless=True)
    context = browser.new_context(ignore_https_errors=True)
    page = context.new_page()
    state = _BrowserState(playwright=pw, browser=browser, context=context, page=page)
    _BROWSER_SESSIONS[session_id] = state
    return state


def _page_snapshot(page: Any, max_links: int = 20) -> Dict[str, Any]:
    title = page.title() or ""
    url = page.url or ""
    text = page.locator("body").inner_text(timeout=3000) if page.locator("body").count() else ""
    text = re.sub(r"\s+", " ", text or "").strip()
    links = []
    buttons = []
    inputs = []
    headings = []
    try:
        anchors = page.locator("a").all()[:max_links]
        for idx, anchor in enumerate(anchors, start=1):
            try:
                href = anchor.get_attribute("href") or ""
                text_label = re.sub(r"\s+", " ", anchor.inner_text(timeout=1000) or "").strip()
                links.append({"index": idx, "text": text_label[:240], "href": href})
            except Exception:
                continue
    except Exception:
        pass
    try:
        button_nodes = page.locator("button, [role='button'], input[type='button'], input[type='submit']").all()[:12]
        for idx, button in enumerate(button_nodes, start=1):
            try:
                text_label = re.sub(r"\s+", " ", button.inner_text(timeout=1000) or "").strip()
                if not text_label:
                    text_label = re.sub(r"\s+", " ", button.get_attribute("value") or "").strip()
                selector = f"text={text_label}" if text_label else ""
                buttons.append({"index": idx, "text": text_label[:240], "selector": selector})
            except Exception:
                continue
    except Exception:
        pass
    try:
        input_nodes = page.locator("input, textarea").all()[:12]
        for idx, node in enumerate(input_nodes, start=1):
            try:
                inputs.append(
                    {
                        "index": idx,
                        "name": (node.get_attribute("name") or "")[:120],
                        "placeholder": (node.get_attribute("placeholder") or "")[:160],
                        "type": (node.get_attribute("type") or "")[:80],
                    }
                )
            except Exception:
                continue
    except Exception:
        pass
    try:
        heading_nodes = page.locator("h1, h2, h3, [role='heading']").all()[:12]
        for idx, node in enumerate(heading_nodes, start=1):
            try:
                text_label = re.sub(r"\s+", " ", node.inner_text(timeout=1000) or "").strip()
                if text_label:
                    headings.append({"index": idx, "text": text_label[:240]})
            except Exception:
                continue
    except Exception:
        pass
    return {
        "url": url,
        "title": title,
        "text_preview": text[:2400],
        "links": links,
        "link_count": len(links),
        "buttons": buttons,
        "inputs": inputs,
        "headings": headings,
    }


def browser_navigate(session_id: str, url: str, wait_until: str = "domcontentloaded", wait_ms: int = 1200) -> Dict[str, Any]:
    state = _ensure_session(session_id)
    state.page.goto(url, wait_until=wait_until, timeout=15000)
    try:
        state.page.wait_for_load_state("networkidle", timeout=5000)
    except Exception:
        pass
    try:
        state.page.wait_for_timeout(max(0, int(wait_ms)))
    except Exception:
        pass
    return _page_snapshot(state.page)


def browser_click(session_id: str, selector: str) -> Dict[str, Any]:
    state = _ensure_session(session_id)
    state.page.locator(selector).first.click(timeout=8000)
    try:
        state.page.wait_for_load_state("domcontentloaded", timeout=5000)
    except Exception:
        pass
    snap = _page_snapshot(state.page)
    snap["clicked_selector"] = selector
    return snap


def browser_type(session_id: str, selector: str, text: str, submit: bool = False) -> Dict[str, Any]:
    state = _ensure_session(session_id)
    target = state.page.locator(selector).first
    target.fill(text, timeout=8000)
    if submit:
        target.press("Enter", timeout=3000)
        try:
            state.page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
    snap = _page_snapshot(state.page)
    snap["typed_selector"] = selector
    snap["submitted"] = submit
    return snap


def browser_scroll(session_id: str, pixels: int = 900) -> Dict[str, Any]:
    state = _ensure_session(session_id)
    state.page.evaluate("(value) => window.scrollBy(0, value)", int(pixels))
    try:
        state.page.wait_for_timeout(900)
    except Exception:
        pass
    snap = _page_snapshot(state.page)
    snap["scrolled_pixels"] = int(pixels)
    return snap


def browser_snapshot(session_id: str, wait_ms: int = 0) -> Dict[str, Any]:
    state = _ensure_session(session_id)
    if wait_ms > 0:
        try:
            state.page.wait_for_timeout(max(0, int(wait_ms)))
        except Exception:
            pass
    return _page_snapshot(state.page)


def browser_screenshot(session_id: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
    state = _ensure_session(session_id)
    base_dir = Path(output_dir or os.path.join(os.getcwd(), ".tmp", "browser"))
    base_dir.mkdir(parents=True, exist_ok=True)
    filename = _safe_name(session_id) + ".png"
    path = base_dir / filename
    state.page.screenshot(path=str(path), full_page=True)
    snap = _page_snapshot(state.page)
    snap["screenshot_path"] = str(path)
    return snap


def close_browser_session(session_id: str) -> None:
    state = _BROWSER_SESSIONS.pop(session_id, None)
    if state is None:
        return
    try:
        state.context.close()
    except Exception:
        pass
    try:
        state.browser.close()
    except Exception:
        pass
    try:
        state.playwright.stop()
    except Exception:
        pass
