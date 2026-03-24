from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class AgentMemory:
    recent_files: list[str] = field(default_factory=list)
    recent_searches: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    web_results: list[dict[str, str]] = field(default_factory=list)
    page_links: list[dict[str, str]] = field(default_factory=list)
    current_page: Optional[str] = None

    def remember_file(self, path: str) -> None:
        path = path.strip()
        if not path:
            return
        self.recent_files = [path] + [p for p in self.recent_files if p != path]
        self.recent_files = self.recent_files[:8]

    def remember_search(self, query: str) -> None:
        query = query.strip()
        if not query:
            return
        self.recent_searches = [query] + [q for q in self.recent_searches if q != query]
        self.recent_searches = self.recent_searches[:8]

    def remember_note(self, note: str) -> None:
        note = note.strip()
        if not note:
            return
        self.notes = [note] + self.notes[:11]

    def remember_web_results(self, results: list[Dict[str, str]]) -> None:
        self.web_results = list(results[:10])

    def remember_page(self, url: str, links: list[Dict[str, str]]) -> None:
        self.current_page = url.strip() or None
        self.page_links = list(links[:20])

    def render(self) -> str:
        parts: list[str] = []
        if self.recent_files:
            parts.append("Recent files: " + ", ".join(self.recent_files))
        if self.recent_searches:
            parts.append("Recent searches: " + " | ".join(self.recent_searches))
        if self.notes:
            parts.append("Notes: " + " | ".join(self.notes[:5]))
        if self.current_page:
            parts.append(f"Current page: {self.current_page}")
        if self.web_results:
            parts.append(
                "Web results: "
                + " | ".join(f"{idx + 1}:{item.get('title') or item.get('url')}" for idx, item in enumerate(self.web_results[:5]))
            )
        if self.page_links:
            parts.append(
                "Page links: "
                + " | ".join(f"{idx + 1}:{item.get('text') or item.get('url')}" for idx, item in enumerate(self.page_links[:5]))
            )
        return "\n".join(parts) if parts else "No working memory yet."
