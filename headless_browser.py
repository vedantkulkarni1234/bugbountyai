"""Headless browser utilities powered by Playwright."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import urlparse

try:  # pragma: no cover - best-effort optional dependency
    from playwright.sync_api import (  # type: ignore
        sync_playwright,
        TimeoutError as PlaywrightTimeoutError,
    )
except ImportError:  # pragma: no cover - Playwright not installed
    sync_playwright = None  # type: ignore
    PlaywrightTimeoutError = Exception  # type: ignore


class HeadlessBrowser:
    """Encapsulates Playwright-powered browsing for DOM and screenshot capture."""

    def __init__(self, output_dir: str = "reports/browser", max_dom_chars: int = 20000):
        self.output_dir = output_dir
        self.screenshot_dir = os.path.join(self.output_dir, "screenshots")
        self.max_dom_chars = max_dom_chars

    def is_available(self) -> bool:
        """Return True if Playwright is available in the current environment."""
        return sync_playwright is not None

    def collect_page_data(self, url: str) -> Dict[str, Any]:
        """Render the target URL headlessly and collect DOM, forms, and screenshots."""
        if not self.is_available():
            return {
                "status": "skipped",
                "reason": "playwright_not_installed",
            }

        self._ensure_directories()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path or "target"
        safe_host = host.replace(":", "_").replace("/", "_")
        screenshot_path = os.path.join(self.screenshot_dir, f"{safe_host}_{timestamp}.png")

        console_logs: List[str] = []
        actions_performed: List[str] = []

        browser = None
        context = None
        try:
            with sync_playwright() as playwright:  # type: ignore[arg-type]
                browser = playwright.chromium.launch(
                    headless=True,
                    args=["--disable-dev-shm-usage", "--no-sandbox"],
                )
                context = browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 720},
                )
                page = context.new_page()
                page.on("dialog", lambda dialog: dialog.dismiss())
                page.on(
                    "console",
                    lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"),
                )

                try:
                    page.goto(url, wait_until="networkidle", timeout=20000)
                except PlaywrightTimeoutError:  # pragma: no cover - network-dependent
                    page.goto(url, wait_until="domcontentloaded", timeout=20000)

                actions_performed.extend(self._simulate_basic_actions(page))
                try:
                    rendered_dom = page.content()
                except PlaywrightTimeoutError:  # pragma: no cover - unlikely
                    rendered_dom = ""
                dom_truncated = len(rendered_dom) > self.max_dom_chars
                if dom_truncated:
                    rendered_dom = rendered_dom[: self.max_dom_chars]

                try:
                    page_title = page.title()
                except PlaywrightTimeoutError:
                    page_title = ""

                screenshot_saved = ""
                try:
                    page.screenshot(path=screenshot_path, full_page=True)
                    screenshot_saved = screenshot_path
                except Exception:
                    screenshot_saved = ""

                forms = self._extract_forms(page)
                script_urls = self._extract_script_urls(page)

                return {
                    "status": "captured",
                    "page_title": page_title,
                    "final_url": page.url,
                    "rendered_dom": rendered_dom,
                    "dom_truncated": dom_truncated,
                    "screenshot_path": screenshot_saved,
                    "actions_performed": actions_performed,
                    "forms": forms,
                    "script_urls": script_urls,
                    "console_logs": console_logs[:20],
                    "collected_at": datetime.now().isoformat(),
                }
        except PlaywrightTimeoutError as err:
            return {
                "status": "error",
                "reason": f"timeout: {err}",
            }
        except Exception as exc:  # pragma: no cover - best effort fallback
            return {
                "status": "error",
                "reason": str(exc),
            }
        finally:
            if context:
                try:
                    context.close()
                except Exception:
                    pass
            if browser:
                try:
                    browser.close()
                except Exception:
                    pass

    def _ensure_directories(self) -> None:
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.screenshot_dir, exist_ok=True)

    def _extract_forms(self, page: Any, limit: int = 5) -> List[Dict[str, Any]]:
        forms_metadata: List[Dict[str, Any]] = []
        try:
            forms = page.query_selector_all("form")
        except Exception:
            return forms_metadata

        for index, form in enumerate(forms[:limit], start=1):
            inputs_info: List[Dict[str, Any]] = []
            try:
                inputs = form.query_selector_all("input, textarea, select")
            except Exception:
                inputs = []
            for field in inputs[:10]:
                try:
                    inputs_info.append(
                        {
                            "name": field.get_attribute("name") or "",
                            "type": field.get_attribute("type") or field.evaluate("el => el.tagName"),
                            "placeholder": field.get_attribute("placeholder") or "",
                        }
                    )
                except Exception:
                    continue
            forms_metadata.append(
                {
                    "index": index,
                    "method": (form.get_attribute("method") or "GET").upper(),
                    "action": form.get_attribute("action") or "",
                    "inputs": inputs_info,
                }
            )
        return forms_metadata

    def _simulate_basic_actions(self, page: Any) -> List[str]:
        actions: List[str] = []
        try:
            page.wait_for_timeout(500)
        except Exception:
            pass

        try:
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            actions.append("scrolled_to_bottom")
        except Exception:
            pass

        try:
            text_input = page.query_selector("input[type='text'], input:not([type]), textarea")
            if text_input:
                text_input.fill("security-scan", timeout=1000)
                actions.append("filled_text_input")
                try:
                    text_input.press("Enter")
                    actions.append("submitted_form_via_enter")
                except Exception:
                    pass
        except Exception:
            pass

        try:
            button = page.query_selector("button, input[type='submit']")
            if button:
                button.click(timeout=1000)
                actions.append("clicked_primary_button")
        except Exception:
            pass

        return actions

    def _extract_script_urls(self, page: Any, limit: int = 20) -> List[str]:
        """
        Extract all JavaScript file URLs from the page.
        
        Args:
            page: Playwright page object
            limit: Maximum number of script URLs to extract
            
        Returns:
            List of script URLs
        """
        script_urls: List[str] = []
        try:
            scripts = page.query_selector_all("script[src]")
        except Exception:
            return script_urls
        
        for script in scripts[:limit]:
            try:
                src = script.get_attribute("src")
                if src:
                    # Convert relative URLs to absolute
                    absolute_url = page.evaluate(
                        f"(src) => new URL(src, document.baseURI).href",
                        src
                    )
                    script_urls.append(absolute_url)
            except Exception:
                continue
        
        return script_urls
