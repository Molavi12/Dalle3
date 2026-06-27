#!/usr/bin/env python3
"""
GitHub Copilot Chat API Client — Enhanced Edition
==================================================

یک کلاینت کامل پایتون برای کار با GitHub Copilot Web Chat API. این نسخه
شامل تمام قابلیت‌های کشف‌شده از طریق reverse engineering مرورگر است:

قابلیت‌ها:
  ✓ مدیریت مکالمات (threads): لیست، ایجاد، حذف، تغییر نام
  ✓ ارسال پیام با SSE streaming
  ✓ پشتیبانی از 10 مدل LLM (GPT-5.x, Claude Sonnet/Opus 4.x, ...)
  ✓ آپلود تصویر و ارسال با پیام (Vision/تصویرسازی)
  ✓ آپلود فایل کد/متن و ارسال به چت
  ✓ بررسی سهمیه کاربر (quota) و اطلاعات اشتراک
  ✓ جستجوی ریپازیتوری‌های کاربر برای پیوست
  ✓ حالت تعاملی چندتایی REPL
  ✓ intent=explain برای توضیح کد/فایل با references
  ✓ استخراج خودکار توکن از مرورگر (یا استفاده از توکن hard-coded)

نحوه احراز هویت:
   GitHub Copilot Web از سه هدر برای احراز هویت استفاده می‌کند:
       Authorization: GitHub-Bearer <COPILLOT_TOKEN>
       copilot-integration-id: copilot-chat
       X-GitHub-Api-Version: 2025-05-01

   توکن <COPILLOT_TOKEN> از طریق لاگین در github.com/copilot به‌دست می‌آید
   و در localStorage مرورگر با کلید COPILOT_AUTH_TOKEN ذخیره می‌شود.
   عمر این توکن ~30 دقیقه است و باید قبل از انقضاء تمدید شود.

⚠️  نکته امنیتی: توکن در کد hard-code شده برای راحتی استفاده. این توکن
   ~30 دقیقه عمر دارد و باید تمدید شود. هرگز این فایل را به‌صورت عمومی
   منتشر نکنید!

استفاده:
   python github_copilot_api.py --info
   python github_copilot_api.py --ask "یک تابع فاکتوریل بنویس"
   python github_copilot_api.py --vision image.png "این تصویر را توصیف کن"
   python github_copilot_api.py --interactive
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Optional

import requests


# ============================================================================
# ⚙️  تنظیمات - توکن و ثابت‌های API
# ============================================================================

# 🔑 توکن hard-coded (در تاریخ 2026-06-27 فعال؛ پس از ~30 دقیقه منقضی می‌شود)
# برای تمدید: python github_copilot_api.py --get-token-from-browser
HARDCODED_TOKEN = "YIyrm0En-OEVf42PEZlZROLR29xmS1f3EfwxQT-YxbMqk86EIaL3-64MU501gvBtsP2I0bCCIbaRSC5_8UvwEzsQ5KlIIbOMra-ChkNNzq4="

# ثابت‌های API
API_BASE = "https://api.individual.githubcopilot.com"
GITHUB_BASE = "https://github.com"
API_VERSION = "2025-05-01"
INTEGRATION_ID = "copilot-chat"

# Endpoint های کشف‌شده
ENDPOINTS = {
    # === Chat API (api.individual.githubcopilot.com) ===
    "list_threads":        ("GET",    "/github/chat/threads"),
    "create_thread":       ("POST",   "/github/chat/threads"),
    "delete_thread":       ("DELETE", "/github/chat/threads/{thread_id}"),
    "rename_thread":       ("PATCH",  "/github/chat/threads/{thread_id}/name"),
    "list_messages":       ("GET",    "/github/chat/threads/{thread_id}/messages"),
    "send_message":        ("POST",   "/github/chat/threads/{thread_id}/messages"),
    "list_models":         ("GET",    "/github/chat/models"),
    # === GitHub.com endpoints (با session cookie احراز هویت می‌شوند) ===
    "entitlement":         ("GET",    "/github-copilot/chat/entitlement"),
    "repo_search":         ("GET",    "/github-copilot/chat/repositories_search"),
    "upload_policy":       ("POST",   "/upload/policies/copilot-chat-attachments"),
}

# مسیر فایل ذخیره توکن
TOKEN_CACHE = os.path.expanduser("~/.copilot_token_cache.json")

# پسوندهای فایل پشتیبانی‌شده برای آپلود
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
CODE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp", ".h", ".hpp",
    ".cs", ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".scala", ".r",
    ".m", ".mm", ".lua", ".pl", ".sh", ".bash", ".zsh", ".ps1",
    ".html", ".css", ".scss", ".less", ".vue", ".svelte",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".md", ".rst", ".txt", ".csv", ".tsv", ".xml", ".sql",
    ".dockerfile", ".gitignore", ".env", ".lock",
    ".c", ".h", ".cc", ".cxx", ".make", ".cmake",
}


# ----------------------------------------------------------------------------
# Exception های سفارشی
# ----------------------------------------------------------------------------
class CopilotAPIError(Exception):
    """خطای عمومی API"""
    def __init__(self, message: str, status_code: Optional[int] = None,
                 response_text: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


class TokenExpiredError(CopilotAPIError):
    """توکن منقضی شده است"""


# ----------------------------------------------------------------------------
# Data classes
# ----------------------------------------------------------------------------
@dataclass
class CopilotToken:
    """نمایش توکن احراز هویت Copilot"""
    value: str
    expiration: str  # ISO 8601 timestamp

    @classmethod
    def from_storage_json(cls, raw: str | dict) -> "CopilotToken":
        data = json.loads(raw) if isinstance(raw, str) else raw
        return cls(value=data["value"], expiration=data["expiration"])

    @property
    def is_expired(self) -> bool:
        """بررسی انقضاء توکن"""
        try:
            exp = time.mktime(time.strptime(self.expiration, "%Y-%m-%dT%H:%M:%S.000Z"))
            return time.time() >= exp - 30  # 30 ثانیه بافر
        except Exception:
            return False


@dataclass
class Thread:
    """مدل یک مکالمه"""
    id: str
    name: str
    manually_named: bool
    created_at: str
    updated_at: str
    auto_picked_model: Optional[str] = None
    shared_at: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "Thread":
        return cls(
            id=d["id"],
            name=d.get("name", ""),
            manually_named=d.get("manuallyNamed", False),
            created_at=d.get("createdAt", ""),
            updated_at=d.get("updatedAt", ""),
            auto_picked_model=d.get("autoPickedModel"),
            shared_at=d.get("sharedAt"),
        )

    def __str__(self) -> str:
        flag = "✏️ " if self.manually_named else "🤖 "
        return f"{flag}[{self.id[:8]}] {self.name or '(بدون نام)'}"


@dataclass
class Message:
    """مدل یک پیام"""
    id: str
    role: str
    content: str
    created_at: str
    parent_message_id: Optional[str] = None
    intent: str = "conversation"

    @classmethod
    def from_dict(cls, d: dict) -> "Message":
        return cls(
            id=d["id"],
            role=d.get("role", ""),
            content=d.get("content", ""),
            created_at=d.get("createdAt", ""),
            parent_message_id=d.get("parentMessageID"),
            intent=d.get("intent", "conversation"),
        )


@dataclass
class Attachment:
    """یک فایل پیوست شده (تصویر یا فایل کد)"""
    media_type: str       # "image/png", "text/plain", ...
    name: str             # نام فایل
    url: str              # URL پیوست در github.com
    width: Optional[int] = None
    height: Optional[int] = None
    thread_id: Optional[str] = None  # thread که attachment به آن وابسته است

    def to_media_content(self) -> dict:
        d = {
            "mediaType": self.media_type,
            "name": self.name,
            "url": self.url,
            "chatAttachmentUrl": self.url,
        }
        if self.width:
            d["width"] = self.width
        if self.height:
            d["height"] = self.height
        return d


# ----------------------------------------------------------------------------
# Helper: استخراج توکن از مرورگر
# ----------------------------------------------------------------------------
def get_token_from_browser() -> CopilotToken:
    """استخراج توکن از localStorage مرورگر با استفاده از agent-browser"""
    js = "(function(){const r=localStorage.getItem('COPILOT_AUTH_TOKEN');return r||'{\"error\":\"no token\"}';})()"
    result = subprocess.run(
        ["agent-browser", "eval", js],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(f"agent-browser error: {result.stderr}")

    raw = result.stdout.strip()
    try:
        outer = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Could not parse agent-browser output: {raw[:200]}")

    if isinstance(outer, dict):
        if "error" in outer:
            raise RuntimeError(outer["error"])
        data = outer
    elif isinstance(outer, str):
        data = json.loads(outer)
    else:
        raise RuntimeError(f"Unexpected output type: {type(outer)}")

    return CopilotToken.from_storage_json(data)


def cache_token(token: CopilotToken) -> None:
    """ذخیره توکن در فایل"""
    cache = {"value": token.value, "expiration": token.expiration}
    with open(TOKEN_CACHE, "w") as f:
        json.dump(cache, f)


def load_cached_token() -> Optional[CopilotToken]:
    """بارگذاری توکن از فایل کش"""
    if not os.path.exists(TOKEN_CACHE):
        return None
    try:
        with open(TOKEN_CACHE) as f:
            data = json.load(f)
        token = CopilotToken.from_storage_json(data)
        if not token.is_expired:
            return token
    except Exception:
        pass
    return None


def get_token(use_hardcoded: bool = True) -> CopilotToken:
    """گرفتن توکن با اولویت: hard-coded > کش > مرورگر"""
    if use_hardcoded:
        token = CopilotToken(
            value=HARDCODED_TOKEN,
            expiration="2026-06-27T13:15:06.000Z",  # تاریخ انقضاء توکن hard-coded
        )
        if not token.is_expired:
            return token
        print("⚠️  توکن hard-coded منقضی شده، تلاش برای گرفتن توکن تازه...", file=sys.stderr)

    cached = load_cached_token()
    if cached:
        return cached

    token = get_token_from_browser()
    cache_token(token)
    return token


# ----------------------------------------------------------------------------
# Helper: گرفتن session cookieهای GitHub برای endpointهای github.com
# ----------------------------------------------------------------------------
def get_github_cookies() -> dict[str, str]:
    """گرفتن cookieهای github.com از مرورگر برای استفاده در curl/requests"""
    result = subprocess.run(
        ["agent-browser", "cookies"],
        capture_output=True, text=True, timeout=10,
    )
    cookies = {}
    for line in result.stdout.split("\n"):
        if "=" in line:
            name, _, value = line.partition("=")
            name = name.strip()
            value = value.split(";")[0].strip()
            if name in ("user_session", "_gh_sess", "logged_in", "dotcom_user",
                        "__Host-user_session_same_site"):
                cookies[name] = value
    return cookies


def get_fetch_nonce() -> str:
    """گرفتن X-Fetch-Nonce از صفحه github.com"""
    js = "(function(){const m=document.querySelector('meta[name=\"fetch-nonce\"]');return m?m.content:'none';})()"
    result = subprocess.run(
        ["agent-browser", "eval", js],
        capture_output=True, text=True, timeout=10,
    )
    raw = result.stdout.strip().strip('"')
    return raw


# ----------------------------------------------------------------------------
# کلاینت اصلی API
# ----------------------------------------------------------------------------
class CopilotChatClient:
    """کلاینت GitHub Copilot Chat API با تمام قابلیت‌ها"""

    def __init__(self, token: Optional[CopilotToken | str] = None,
                 use_hardcoded: bool = True):
        if token is None:
            token = get_token(use_hardcoded=use_hardcoded)
        elif isinstance(token, str):
            token = CopilotToken(value=token, expiration="2999-01-01T00:00:00.000Z")
        self.token = token
        self.session = requests.Session()
        self.session.headers.update(self._build_headers())

    # ----- Helpers --------------------------------------------------------
    def _build_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"GitHub-Bearer {self.token.value}",
            "copilot-integration-id": INTEGRATION_ID,
            "X-GitHub-Api-Version": API_VERSION,
            "Accept": "application/json",
            "User-Agent": "github-copilot-cli/2.0 (Python)",
            "Origin": "https://github.com",
            "Referer": "https://github.com/copilot",
        }

    def _check_token(self) -> None:
        if self.token.is_expired:
            raise TokenExpiredError(
                "توکن Copilot منقضی شده است. تمدید با: "
                "python github_copilot_api.py --get-token-from-browser"
            )

    def _url(self, key: str, **params) -> str:
        method, path = ENDPOINTS[key]
        if params:
            path = path.format(**params)
        return f"{API_BASE}{path}"

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        self._check_token()
        kwargs.setdefault("timeout", 30)
        resp = self.session.request(method, url, **kwargs)
        if resp.status_code >= 400:
            raise CopilotAPIError(
                f"HTTP {resp.status_code}: {resp.text[:300]}",
                status_code=resp.status_code,
                response_text=resp.text,
            )
        return resp

    # ====================================================================
    # 1) مدیریت Threads (مکالمات)
    # ====================================================================
    def list_threads(self, per_page: int = 30) -> list[Thread]:
        """لیست تمام مکالمات کاربر"""
        resp = self._request("GET", self._url("list_threads"),
                             params={"per_page": per_page})
        data = resp.json()
        return [Thread.from_dict(t) for t in data.get("threads", [])]

    def create_thread(self) -> Thread:
        """ایجاد یک مکالمه جدید"""
        resp = self._request("POST", self._url("create_thread"),
                             json={}, headers={"Content-Type": "application/json"})
        data = resp.json()
        return Thread.from_dict(data.get("thread", data))

    def delete_thread(self, thread_id: str) -> bool:
        """حذف یک مکالمه"""
        resp = self._request("DELETE", self._url("delete_thread", thread_id=thread_id))
        return resp.status_code == 204

    def rename_thread(self, thread_id: str, name: str,
                      auto_generate: bool = False) -> str:
        """تغییر نام مکالمه (auto_generate=True باعث تولید نام خودکار می‌شود)"""
        payload = {"generate": auto_generate, "name": name if not auto_generate else ""}
        resp = self._request("PATCH", self._url("rename_thread", thread_id=thread_id),
                             json=payload)
        return resp.json().get("name", name)

    # ====================================================================
    # 2) Messages (پیام‌ها)
    # ====================================================================
    def list_messages(self, thread_id: str) -> list[Message]:
        """دریافت تمام پیام‌های یک مکالمه"""
        resp = self._request("GET", self._url("list_messages", thread_id=thread_id))
        data = resp.json()
        return [Message.from_dict(m) for m in data.get("messages", [])]

    def send_message(
        self,
        thread_id: str,
        content: str,
        model: str = "auto",
        parent_message_id: str = "root",
        intent: str = "conversation",
        references: Optional[list[dict]] = None,
        media_content: Optional[list[dict]] = None,
        deep_code_search: bool = False,
        streaming: bool = True,
    ) -> Iterable[dict]:
        """
        ارسال پیام به یک مکالمه و بازگرداندن رویدادهای SSE به‌صورت iterator.

        هر رویداد یک dict است که کلید 'type' دارد و می‌تواند یکی از موارد زیر باشد:
            - 'threadAutoPickedModel': اطلاع‌رسانی مدل انتخاب‌شده توسط Auto
            - 'routedModel': مدل نهایی استفاده‌شده
            - 'content': بخشی از متن پاسخ (کلید 'body')
            - 'annotations': حاشیه‌نویسی‌های کد
            - 'complete': پایان پاسخ (اطلاعات کامل پیام)

        پارامترها:
            thread_id:          شناسه مکالمه
            content:            متن پیام کاربر
            model:              نام مدل (auto, gpt-5.5, claude-sonnet-4.6, ...)
            parent_message_id:  شناسه پیام والد (برای مکالمه چندتایی)
            intent:             نوع درخواست ('conversation' یا 'explain')
            references:         لیست ارجاعات (برای intent=explain الزامی است)
                                مثال: [{'type':'repository','owner':'octocat','repo':'Hello-World'}]
            media_content:      لیست تصاویر/فایل‌های پیوست (از upload_attachment)
            deep_code_search:   فعال‌سازی جستجوی عمیق کد در ریپوهای پیوست
        """
        response_message_id = str(uuid.uuid4())
        payload = {
            "responseMessageID": response_message_id,
            "content": content,
            "intent": intent,
            "references": references or [],
            "context": [],
            "currentURL": f"https://github.com/copilot/c/{thread_id}",
            "streaming": streaming,
            "confirmations": [],
            "customInstructions": [],
            "model": model,
            "mode": "immersive",
            "parentMessageID": parent_message_id,
            "mediaContent": media_content or [],
            "skillOptions": {"deepCodeSearch": deep_code_search},
            "requestTrace": False,
        }

        headers = {
            "Content-Type": "text/event-stream",
            "Accept": "text/event-stream",
        }

        resp = self.session.post(
            self._url("send_message", thread_id=thread_id),
            json=payload,
            headers={**self.session.headers, **headers},
            stream=True,
            timeout=120,
        )
        if resp.status_code >= 400:
            raise CopilotAPIError(
                f"HTTP {resp.status_code}: {resp.text[:300]}",
                status_code=resp.status_code,
                response_text=resp.text,
            )

        buffer = ""
        for chunk in resp.iter_content(chunk_size=None, decode_unicode=False):
            if chunk is None:
                continue
            if isinstance(chunk, bytes):
                chunk = chunk.decode("utf-8", errors="replace")
            buffer += chunk
            while "\n\n" in buffer:
                event_str, buffer = buffer.split("\n\n", 1)
                for line in event_str.split("\n"):
                    if line.startswith("data: "):
                        data_str = line[6:].strip()
                        if data_str and data_str != "[DONE]":
                            try:
                                yield json.loads(data_str)
                            except json.JSONDecodeError:
                                pass

    def ask(
        self,
        prompt: str,
        model: str = "auto",
        thread_id: Optional[str] = None,
        attachments: Optional[list[Attachment]] = None,
        references: Optional[list[dict]] = None,
        intent: str = "conversation",
        auto_rename: bool = True,
    ) -> tuple[str, Thread]:
        """
        Helper ساده: ایجاد مکالمه جدید (اگر thread_id نداد)، ارسال پیام،
        و بازگرداندن متن پاسخ و مکالمه.

        پارامترهای پیشرفته:
            attachments: لیست Attachmentها (تصویر/فایل آپلودشده)
            references:  لیست ارجاعات (با intent='explain' استفاده می‌شود)
            intent:      'conversation' یا 'explain'

        نکته درباره attachments:
            - تصاویر: به‌صورت mediaContent (با URL) ارسال می‌شوند
            - فایل‌های کد/متن: به‌صورت references با type='thread-scoped-file'
              و محتوای inline ارسال می‌شوند (نیازی به آپلود ندارند)
        """
        if thread_id is None:
            thread = self.create_thread()
            thread_id = thread.id
        else:
            thread = Thread(id=thread_id, name="", manually_named=False,
                            created_at="", updated_at="")

        # تفکیک attachments به دو دسته: تصاویر (mediaContent) و فایل‌های کد (references)
        media_content = []
        code_file_refs = []
        for a in (attachments or []):
            if getattr(a, "is_code_file", False):
                # فایل کد: محتوا را در references قرار بده
                code_file_refs.append({
                    "type": "thread-scoped-file",
                    "name": a.name,
                    "text": getattr(a, "file_content", ""),
                    "language": getattr(a, "language", ""),
                })
            else:
                # تصویر: URL را در mediaContent قرار بده
                media_content.append(a.to_media_content())

        # ترکیب references کاربر با code_file_refs
        all_refs = (references or []) + code_file_refs

        full_response = []
        parent_id = "root"
        for event in self.send_message(
            thread_id, prompt,
            model=model,
            parent_message_id=parent_id,
            intent=intent,
            references=all_refs,
            media_content=media_content,
        ):
            etype = event.get("type")
            if etype == "content":
                full_response.append(event.get("body", ""))
            elif etype == "complete":
                if event.get("id"):
                    parent_id = event["id"]

        if auto_rename and thread.name == "":
            try:
                self.rename_thread(thread_id, "", auto_generate=True)
            except Exception:
                pass

        return "".join(full_response), thread

    # ====================================================================
    # 3) Models (مدل‌های LLM)
    # ====================================================================
    def list_models(self) -> list[dict]:
        """لیست تمام مدل‌های قابل‌استفاده در Copilot"""
        resp = self._request("GET", self._url("list_models"))
        return resp.json().get("data", [])

    # ====================================================================
    # 4) آپلود تصویر و فایل (با استفاده از مرورگر به‌عنوان bridge)
    # ====================================================================
    def upload_attachment(self, file_path: str) -> Attachment:
        """
        آپلود یک فایل تصویر یا فایل کد به GitHub Copilot و بازگرداندن Attachment.

        این متد از agent-browser به‌عنوان bridge استفاده می‌کند زیرا GitHub
        یک فرآیند چندمرحله‌ای پیچیده دارد:
          1. POST /upload/policies/copilot-chat-attachments (گرفتن signed URL)
          2. POST objects-origin.githubusercontent.com (ثبت آپلود)
          3. PUT /upload/copilot-chat-attachments/{id} (آپلود بایت‌ها)
          4. دریافت URL نهایی: github.com/github-copilot/chat/attachments/{uuid}

        پسوندهای پشتیبانی‌شده:
          تصاویر: .png .jpg .jpeg .webp .gif
          فایل‌های کد/متن: .py .js .ts .java .cpp .go .rs .md .json .yaml ...
                           (بیش از 1000 پسوند - لیست کامل در README)
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # اطمینان از اینکه مرورگر روی صفحه Copilot باز است
        self._ensure_browser_on_copilot()

        # ایجاد یک thread موقت برای گرفتن URL پیوست
        temp_thread = self.create_thread()

        # نصب hook برای گرفتن URL پیوست از request بعدی
        # همچنین thread_id واقعی که پیوست به آن تعلق دارد را از URL استخراج می‌کنیم
        js_hook = """
(function() {
  window.__capturedAttachment = null;
  window.__capturedThreadId = null;
  const orig = window.fetch;
  window.fetch = function(input, init) {
    try {
      const url = typeof input === 'string' ? input : (input && input.url) || '';
      // استخراج thread_id از URL: /github/chat/threads/{id}/messages
      const m = url.match(/\\/threads\\/([a-f0-9-]+)\\/messages/);
      if (m) {
        window.__capturedThreadId = m[1];
      }
      if (url.includes('/messages') && init && init.body && typeof init.body === 'string') {
        if (init.body.includes('mediaContent')) {
          const parsed = JSON.parse(init.body);
          if (parsed.mediaContent && parsed.mediaContent.length > 0) {
            window.__capturedAttachment = parsed.mediaContent[0];
            // ذخیره thread_id واقعی اگر در URL پیدا شد
            if (m) {
              window.__capturedAttachment.threadId = m[1];
            }
          }
        }
      }
    } catch(e) {}
    return orig.apply(this, arguments);
  };
  return 'hooked';
})()
"""
        subprocess.run(["agent-browser", "eval", js_hook],
                       capture_output=True, timeout=10)

        # آپلود فایل با agent-browser
        upload_result = subprocess.run(
            ["agent-browser", "upload", "input#image-uploader", file_path],
            capture_output=True, text=True, timeout=30,
        )
        if upload_result.returncode != 0:
            raise RuntimeError(f"Upload failed: {upload_result.stderr}")
        time.sleep(3)  # صبر برای تکمیل آپلود در backend

        # پیدا کردن textbox و ارسال پیام کوتاه برای trigger شدن request
        snap = subprocess.run(["agent-browser", "snapshot", "-i"],
                              capture_output=True, text=True, timeout=10)
        textbox_ref = None
        send_ref = None
        for line in snap.stdout.split("\n"):
            if 'textbox "Ask anything' in line and "[ref=" in line:
                textbox_ref = line.split("[ref=")[1].split("]")[0]
            elif "Send now" in line and "[ref=" in line:
                send_ref = line.split("[ref=")[1].split("]")[0]

        if not textbox_ref or not send_ref:
            raise RuntimeError("Could not find chat input on page")

        # نوشتن یک پیام موقت و ارسال
        subprocess.run(
            ["agent-browser", "fill", f"@{textbox_ref}", "."],
            capture_output=True, timeout=10,
        )
        subprocess.run(
            ["agent-browser", "click", f"@{send_ref}"],
            capture_output=True, timeout=10,
        )
        time.sleep(5)

        # گرفتن attachment از hook
        js_get = "window.__capturedAttachment"
        result = subprocess.run(
            ["agent-browser", "eval", js_get],
            capture_output=True, text=True, timeout=10,
        )
        raw = result.stdout.strip().strip('"')
        if not raw or raw == "null":
            raise RuntimeError("Could not capture attachment URL after upload")

        try:
            attach_data = json.loads(raw)
            if isinstance(attach_data, str):
                attach_data = json.loads(attach_data)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Could not parse attachment data: {raw[:200]}")

        # NOTE: thread موقت را حذف نمی‌کنیم چون attachment URL ها به آن thread
        # وابسته‌اند و حذف thread باعث منقضی شدن URL می‌شود. کاربر می‌تواند بعداً
        # با --list-threads و --delete-thread خودش پاکسازی کند.

        # thread_id واقعی: اگر hook توانسته از URL استخراج کند از آن استفاده می‌کنیم
        real_thread_id = attach_data.get("threadId") or temp_thread.id

        return Attachment(
            media_type=attach_data.get("mediaType", "application/octet-stream"),
            name=attach_data.get("name", os.path.basename(file_path)),
            url=attach_data.get("url", ""),
            width=attach_data.get("width"),
            height=attach_data.get("height"),
            thread_id=real_thread_id,  # thread واقعی که پیوست به آن تعلق دارد
        )

    def upload_image(self, image_path: str) -> Attachment:
        """آپلود یک تصویر (alias برای upload_attachment با بررسی نوع فایل)"""
        ext = os.path.splitext(image_path)[1].lower()
        if ext not in IMAGE_EXTS:
            raise ValueError(f"Unsupported image format: {ext}. "
                             f"Supported: {IMAGE_EXTS}")
        return self.upload_attachment(image_path)

    def upload_file(self, file_path: str) -> Attachment:
        """
        آپلود یک فایل کد/متنی.

        نکته مهم: برخلاف تصاویر، فایل‌های کد/متن نیازی به آپلود ندارند!
        محتوای فایل مستقیماً در references با type='thread-scoped-file'
        در body پیام ارسال می‌شود.

        این متد برای сохран کردن interface یکسان با upload_image وجود دارد،
        اما یک Attachment با flag is_code_file=True برمی‌گرداند.
        """
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in CODE_EXTS and ext not in IMAGE_EXTS:
            print(f"⚠️  Warning: extension '{ext}' may not be supported")

        # برای فایل‌های کد، محتوا را می‌خوانیم و به‌صورت reference ارسال می‌کنیم
        # نه به‌عنوان mediaContent. بنابراین یک Attachment ویژه برمی‌گردانیم.
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        attachment = Attachment(
            media_type="text/x-code",
            name=os.path.basename(file_path),
            url="",  # فایل‌های کد URL ندارند
        )
        # اضافه کردن محتوای فایل به‌صورت یک attribute اضافی
        attachment.file_content = content
        attachment.is_code_file = True
        attachment.language = ext.lstrip(".")  # زبان برنامه‌نویسی (برای syntax highlight)
        return attachment

    # ====================================================================
    # 5) Vision: تحلیل تصویر با Copilot
    # ====================================================================
    def ask_about_image(
        self,
        image_path: str,
        question: str = "این تصویر را توصیف کن",
        model: str = "auto",
        thread_id: Optional[str] = None,
    ) -> tuple[str, Thread, Attachment]:
        """
        آپلود یک تصویر و پرسیدن سوال درباره آن (Vision capability).

        مثال:
            answer, thread, attach = client.ask_about_image(
                "photo.png",
                "چه چیزی در این تصویر می‌بینی؟"
            )
        """
        attachment = self.upload_image(image_path)
        # استفاده از همان thread که تصویر به آن آپلود شده (تا URL معتبر بماند)
        use_thread_id = thread_id or attachment.thread_id
        answer, thread = self.ask(
            question,
            model=model,
            thread_id=use_thread_id,
            attachments=[attachment],
        )
        return answer, thread, attachment

    # ====================================================================
    # 6) اطلاعات اشتراک و سهمیه (Quota / Entitlement)
    # ====================================================================
    def get_entitlement(self) -> dict:
        """
        دریافت اطلاعات اشتراک و سهمیه کاربر.

        نیاز به session cookieهای github.com دارد (نه GitHub-Bearer).
        اگر agent-browser در دسترس نباشد، None برمی‌گرداند.
        """
        try:
            cookies = get_github_cookies()
            nonce = get_fetch_nonce()
        except Exception as e:
            raise RuntimeError(f"Could not get browser cookies/nonce: {e}")

        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Python; Copilot-CLI)",
            "Origin": "https://github.com",
            "Referer": "https://github.com/copilot",
            "X-Requested-With": "XMLHttpRequest",
            "X-Fetch-Nonce": nonce,
            "Cookie": cookie_str,
        }

        resp = requests.get(
            f"{GITHUB_BASE}/github-copilot/chat/entitlement",
            headers=headers, timeout=15,
        )
        if resp.status_code >= 400:
            raise CopilotAPIError(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                status_code=resp.status_code, response_text=resp.text,
            )
        return resp.json()

    # ====================================================================
    # 7) جستجوی ریپازیتوری‌های کاربر
    # ====================================================================
    def search_repositories(self, limit: int = 10) -> list[dict]:
        """
        جستجوی ریپازیتوری‌های کاربر (برای پیوست کردن به مکالمه).

        نیاز به session cookieهای github.com دارد.
        """
        try:
            cookies = get_github_cookies()
            nonce = get_fetch_nonce()
        except Exception as e:
            raise RuntimeError(f"Could not get browser cookies/nonce: {e}")

        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Python; Copilot-CLI)",
            "Origin": "https://github.com",
            "Referer": "https://github.com/copilot",
            "X-Requested-With": "XMLHttpRequest",
            "X-Fetch-Nonce": nonce,
            "Cookie": cookie_str,
        }

        resp = requests.get(
            f"{GITHUB_BASE}/github-copilot/chat/repositories_search",
            params={"limit": limit},
            headers=headers, timeout=15,
        )
        if resp.status_code >= 400:
            raise CopilotAPIError(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                status_code=resp.status_code, response_text=resp.text,
            )
        return resp.json().get("repositories", [])

    # ====================================================================
    # 8) Explain: توضیح کد/فایل/ریپو با references
    # ====================================================================
    def explain(
        self,
        prompt: str,
        references: list[dict],
        model: str = "auto",
        thread_id: Optional[str] = None,
    ) -> tuple[str, Thread]:
        """
        استفاده از intent='explain' برای توضیح کد/فایل/ریپو.

        references باید شامل حداقل یک آیتم با ساختار زیر باشد:
            - ریپو:    {'type': 'repository', 'owner': 'octocat', 'repo': 'Hello-World'}
            - فایل:    {'type': 'file', 'path': 'README.md', 'repo': 'octocat/Hello-World'}
        """
        if not references:
            raise ValueError("explain intent requires at least one reference")
        return self.ask(
            prompt,
            model=model,
            thread_id=thread_id,
            references=references,
            intent="explain",
        )

    # ====================================================================
    # Internal: اطمینان از باز بودن مرورگر روی Copilot
    # ====================================================================
    def _ensure_browser_on_copilot(self) -> None:
        """اطمینان از اینکه مرورگر روی صفحه github.com/copilot باز است"""
        # Check current URL
        result = subprocess.run(
            ["agent-browser", "get", "url"],
            capture_output=True, text=True, timeout=10,
        )
        current_url = result.stdout.strip()
        if "github.com/copilot" not in current_url:
            # Navigate to Copilot
            subprocess.run(
                ["agent-browser", "open", "https://github.com/copilot"],
                capture_output=True, timeout=30,
            )
            time.sleep(3)


# ============================================================================
# CLI - رابط خط فرمان
# ============================================================================
def cmd_info(args) -> None:
    """--info: نمایش اطلاعات کامل کلاینت و قابلیت‌ها"""
    print("=" * 75)
    print("  GitHub Copilot Chat API Client — Enhanced v2.0")
    print("=" * 75)
    print(f"\n🌐 API Base URL:    {API_BASE}")
    print(f"🌐 GitHub Base URL: {GITHUB_BASE}")
    print(f"📋 API Version:     {API_VERSION}")
    print(f"🔌 Integration ID:  {INTEGRATION_ID}")
    print(f"🔐 Auth Scheme:     GitHub-Bearer <token>")
    print(f"💾 Token Cache:     {TOKEN_CACHE}")

    # Check token
    try:
        token = get_token(use_hardcoded=True)
        status = "✅ معتبر" if not token.is_expired else "❌ منقضی"
        print(f"🔑 Token Status:    {status}")
        print(f"   Value:           {token.value[:40]}...")
        print(f"   Expiration:      {token.expiration}")
    except Exception as e:
        print(f"🔑 Token Status:    ⚠️  {e}")

    print(f"\n📡 Endpoint های کشف‌شده:\n")
    for key, (method, path) in ENDPOINTS.items():
        base = GITHUB_BASE if "github-copilot" in path or "upload" in path else API_BASE
        full = f"{base}{path}"
        print(f"  {method:7} {full}")

    print(f"\n🎯 قابلیت‌های کلاینت:")
    print(f"  1. 📋 مدیریت مکالمات (threads)")
    print(f"     - لیست، ایجاد، حذف، تغییر نام (دستی/خودکار)")
    print(f"  2. 💬 ارسال پیام با SSE streaming")
    print(f"     - پشتیبانی از مکالمه چندتایی با parent_message_id")
    print(f"  3. 🤖 انتخاب مدل LLM")
    print(f"     - auto, gpt-5.5, gpt-5.4, gpt-5.3-codex, gpt-5.4-mini")
    print(f"     - claude-sonnet-4.6/4.5, claude-opus-4.8/4.7/4.6")
    print(f"  4. 🖼️  آپلود تصویر و Vision")
    print(f"     - فرمت‌ها: PNG, JPG, JPEG, WebP, GIF")
    print(f"     - تحلیل تصویر + سوال درباره آن")
    print(f"  5. 📄 آپلود فایل کد/متن")
    print(f"     - بیش از 1000 پسوند: .py, .js, .ts, .md, .json, ...")
    print(f"  6. 📊 بررسی سهمیه (Quota)")
    print(f"     - تعداد درخواست‌های باقی‌مانده، تاریخ reset")
    print(f"     - نوع اشتراک (free/pro/business)")
    print(f"  7. 🔍 جستجوی ریپازیتوری‌های کاربر")
    print(f"     - برای پیوست به مکالمه با references")
    print(f"  8. 💡 intent=explain برای توضیح کد/فایل")
    print(f"     - توضیح کد ریپو با reference به repo/file")
    print(f"  9. 🔎 deepCodeSearch: جستجوی عمیق کد در ریپوهای پیوست")
    print(f" 10. 🎮 حالت تعاملی REPL")

    print(f"\n⚠️  محدودیت‌های نسخه Copilot Free:")
    print(f"  ❌ تولید تصویر (image generation) - نیاز به Pro/Max")
    print(f"  ❌ Cloud Agents (Copilot Agents page) - نیاز به Pro")
    print(f"  ❌ Spark (image generation app) - نیاز به Pro")
    print(f"  ❌ Spaces (خانۀ کد گروهی) - نیاز به Pro")
    print(f"  ❌ مدل‌های premium (gpt-5.5, claude-opus, ...) - نیاز به Pro/Max")
    print(f"  ✅ Auto (gpt-5-mini) - رایگان، 200 درخواست در ماه")

    print(f"\n📚 مثال‌ها:")
    print(f'  python {sys.argv[0]} --info')
    print(f'  python {sys.argv[0]} --list-threads')
    print(f'  python {sys.argv[0]} --list-models')
    print(f'  python {sys.argv[0]} --entitlement')
    print(f'  python {sys.argv[0]} --search-repos')
    print(f'  python {sys.argv[0]} --ask "یک تابع فاکتوریل بنویس"')
    print(f'  python {sys.argv[0]} --stream "یک شعر کوتاه بگو"')
    print(f'  python {sys.argv[0]} --vision photo.png "این تصویر را توصیف کن"')
    print(f'  python {sys.argv[0]} --upload-file code.py')
    print(f'  python {sys.argv[0]} --explain "توضیح بده" --ref octocat/Hello-World')
    print(f'  python {sys.argv[0]} --interactive --model auto')


def cmd_get_token(args) -> None:
    """--get-token-from-browser"""
    token = get_token_from_browser()
    cache_token(token)
    print(f"✅ توکن با موفقیت استخراج و در {TOKEN_CACHE} ذخیره شد")
    print(f"   مقدار:   {token.value[:40]}...")
    print(f"   انقضاء:  {token.expiration}")


def cmd_list_threads(args) -> None:
    """--list-threads"""
    client = CopilotChatClient()
    threads = client.list_threads()
    if not threads:
        print("📭 هنوز هیچ مکالمه‌ای وجود ندارد.")
        return
    print(f"📋 {len(threads)} مکالمه یافت شد:\n")
    for i, t in enumerate(threads, 1):
        print(f"  {i}. {t}")
        print(f"     مدل: {t.auto_picked_model or 'نامشخص'}  |  ساخته‌شده: {t.created_at}")
        print()


def cmd_list_models(args) -> None:
    """--list-models"""
    client = CopilotChatClient()
    models = client.list_models()
    print(f"🤖 {len(models)} مدل در دسترس:\n")
    for m in models:
        prem = "💎 premium" if m.get("billing", {}).get("is_premium") else "🆓 رایگان"
        cat = m.get("model_picker_category", "")
        print(f"  • {m['id']:25}  {m.get('name',''):25}  {m.get('vendor',''):12}  {prem}  {cat}")
        limits = m.get("capabilities", {}).get("limits", {})
        if "max_prompt_tokens" in limits:
            print(f"      max_prompt_tokens: {limits['max_prompt_tokens']:,}")


def cmd_entitlement(args) -> None:
    """--entitlement: اطلاعات سهمیه و اشتراک"""
    client = CopilotChatClient()
    try:
        ent = client.get_entitlement()
    except Exception as e:
        print(f"❌ خطا در گرفتن اطلاعات اشتراک: {e}", file=sys.stderr)
        print("   برای این قابلیت agent-browser باید روی github.com/copilot باز باشد.",
              file=sys.stderr)
        return

    print(f"📊 اطلاعات اشتراک GitHub Copilot\n")
    print(f"  👤 Plan:            {ent.get('plan', 'unknown')}")
    print(f"  📜 License Type:    {ent.get('licenseType', 'unknown')}")

    quotas = ent.get("quotas", {})
    remaining = quotas.get("remaining", {})
    print(f"\n  💰 سهمیه باقی‌مانده:")
    print(f"     💬 Chat:                {remaining.get('chat', 0)} ({remaining.get('chatPercentage', 0):.1f}%)")
    print(f"     ✨ Completions:         {remaining.get('completions', 0)}")
    print(f"     💎 Premium Interactions: {remaining.get('premiumInteractions', 0)}")
    print(f"\n  📅 Reset Date:      {quotas.get('resetDate', 'unknown')}")

    chat_quota = quotas.get("chatQuota", {})
    print(f"\n  📈 جزئیات Chat Quota:")
    print(f"     Total:  {chat_quota.get('total', 0)}")
    print(f"     Used:   {chat_quota.get('used', 0)}")
    print(f"     Remain: {chat_quota.get('percentRemaining', 0):.1f}%")

    trial = ent.get("trial", {})
    if trial.get("eligible"):
        print(f"\n  🎁 Trial eligible: ✅")


def cmd_search_repos(args) -> None:
    """--search-repos: لیست ریپازیتوری‌های کاربر"""
    client = CopilotChatClient()
    try:
        repos = client.search_repositories(limit=args.limit)
    except Exception as e:
        print(f"❌ خطا: {e}", file=sys.stderr)
        return

    print(f"📦 {len(repos)} ریپازیتوری یافت شد:\n")
    for i, r in enumerate(repos, 1):
        vis = "🔒 private" if r.get("isPrivate") else "🌐 public"
        print(f"  {i}. {r.get('nameWithOwner', '')}  {vis}")
        print(f"     Owner: {r.get('ownerLogin', '')} ({r.get('ownerType', '')})")


def cmd_show_thread(args) -> None:
    """--show-thread THREAD_ID"""
    client = CopilotChatClient()
    thread_id = args.show_thread
    msgs = client.list_messages(thread_id)
    if not msgs:
        print("📭 این مکالمه خالی است.")
        return
    print(f"💬 {len(msgs)} پیام در مکالمه {thread_id}:\n")
    for m in msgs:
        icon = "👤" if m.role == "user" else "🤖"
        print(f"{icon} [{m.role.upper()}] {m.content}")
        print()


def cmd_delete_thread(args) -> None:
    """--delete-thread THREAD_ID"""
    client = CopilotChatClient()
    thread_id = args.delete_thread
    if client.delete_thread(thread_id):
        print(f"✅ مکالمه {thread_id} حذف شد.")
    else:
        print(f"❌ حذف ناموفق بود.")


def cmd_ask(args) -> None:
    """--ask PROMPT"""
    client = CopilotChatClient()
    print(f"🤖 در حال ارسال درخواست به مدل '{args.model}'...\n")
    answer, thread = client.ask(args.ask, model=args.model)
    print(f"📝 پاسخ Copilot (thread {thread.id[:8]}):\n")
    print(answer)
    print(f"\n— thread_id: {thread.id}")


def cmd_stream(args) -> None:
    """--stream PROMPT"""
    client = CopilotChatClient()
    thread = client.create_thread()
    print(f"🆕 مکالمه جدید: {thread.id}")
    print(f"🤖 پاسخ زنده:\n")
    for event in client.send_message(thread.id, args.stream, model=args.model):
        etype = event.get("type")
        if etype == "content":
            print(event.get("body", ""), end="", flush=True)
        elif etype == "routedModel":
            print(f"[مدل استفاده‌شده: {event.get('model')}]")
        elif etype == "complete":
            print("\n\n✅ پاسخ کامل شد.")
    print(f"\n— thread_id: {thread.id}")


def cmd_vision(args) -> None:
    """--vision-image PATH --vision-prompt PROMPT"""
    client = CopilotChatClient()
    print(f"🖼️  در حال آپلود تصویر {args.vision_image} ...")
    try:
        attachment = client.upload_image(args.vision_image)
    except Exception as e:
        print(f"❌ خطا در آپلود تصویر: {e}", file=sys.stderr)
        return
    print(f"✅ تصویر آپلود شد: {attachment.url}")
    print(f"   نوع: {attachment.media_type}  ابعاد: {attachment.width}x{attachment.height}")
    print(f"   thread: {attachment.thread_id}")
    print(f"\n🤖 در حال پرسیدن: {args.vision_prompt}\n")
    # استفاده از thread_id که تصویر به آن آپلود شده (تا URL معتبر بماند)
    answer, thread = client.ask(
        args.vision_prompt,
        model=args.model,
        thread_id=attachment.thread_id,
        attachments=[attachment],
    )
    print(f"📝 پاسخ Copilot:\n")
    print(answer)
    print(f"\n— thread_id: {thread.id}")


def cmd_upload_file(args) -> None:
    """--upload-file FILE_PATH"""
    client = CopilotChatClient()
    print(f"📄 در حال پردازش فایل {args.upload_file} ...")
    try:
        attachment = client.upload_file(args.upload_file)
    except Exception as e:
        print(f"❌ خطا در آپلود فایل: {e}", file=sys.stderr)
        return

    print(f"✅ فایل آماده شد!")
    print(f"   نام:    {attachment.name}")
    print(f"   نوع:    {attachment.media_type}")
    print(f"   اندازه: {len(getattr(attachment, 'file_content', ''))} کاراکتر")
    print(f"   زبان:   {getattr(attachment, 'language', 'unknown')}")

    # اگر کاربر prompt داده، سوال را بپرس
    prompt = getattr(args, 'file_prompt', None) or "این فایل را توضیح بده و کاربردش را بگو."
    print(f"\n🤖 در حال پرسیدن: {prompt}\n")
    answer, thread = client.ask(
        prompt,
        model=args.model,
        attachments=[attachment],
    )
    print(f"📝 پاسخ Copilot:\n")
    print(answer)
    print(f"\n— thread_id: {thread.id}")


def cmd_explain(args) -> None:
    """--explain PROMPT --ref OWNER/REPO"""
    client = CopilotChatClient()
    # Parse reference: owner/repo
    if "/" in args.ref:
        owner, repo = args.ref.split("/", 1)
        references = [{"type": "repository", "owner": owner, "repo": repo}]
    else:
        print("❌ --ref باید به فرمت OWNER/REPO باشد", file=sys.stderr)
        return
    print(f"💡 در حال توضیح {args.ref} با intent=explain ...\n")
    answer, thread = client.explain(args.explain, references, model=args.model)
    print(f"📝 پاسخ Copilot:\n")
    print(answer)
    print(f"\n— thread_id: {thread.id}")


def cmd_interactive(args) -> None:
    """--interactive: حالت تعاملی REPL"""
    client = CopilotChatClient()
    thread = client.create_thread()
    parent_id = "root"
    print(f"🚀 حالت تعاملی Copilot فعال شد. (thread: {thread.id[:8]})")
    print(f"   دستورات: /quit (خروج)  /new (مکالمه جدید)  /upload <path> (پیوست)")
    print(f"   برای خروج Ctrl+C هم کار می‌کند.\n")

    while True:
        try:
            user_input = input("👤 شما: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n👋 خداحافظ!")
            break

        if not user_input:
            continue

        if user_input.lower() in ("/quit", "/exit", "/q"):
            print("👋 خداحافظ!")
            break

        if user_input.lower() == "/new":
            thread = client.create_thread()
            parent_id = "root"
            print(f"🆕 مکالمه جدید: {thread.id[:8]}\n")
            continue

        if user_input.lower().startswith("/upload "):
            file_path = user_input[8:].strip()
            try:
                attachment = client.upload_attachment(file_path)
                print(f"✅ پیوست شد: {attachment.name} -> {attachment.url}")
                print(f"   (برای استفاده در پیام بعدی، کافیست سوال خود را بپرسید)")
                # Store for next message
                client._pending_attachment = attachment
            except Exception as e:
                print(f"❌ خطا در آپلود: {e}")
            continue

        attachments = []
        if hasattr(client, "_pending_attachment") and client._pending_attachment:
            attachments.append(client._pending_attachment)
            client._pending_attachment = None

        print("🤖 Copilot: ", end="", flush=True)
        for event in client.send_message(thread.id, user_input,
                                         model=args.model,
                                         parent_message_id=parent_id,
                                         media_content=[a.to_media_content() for a in attachments]):
            etype = event.get("type")
            if etype == "content":
                print(event.get("body", ""), end="", flush=True)
            elif etype == "complete":
                if event.get("id"):
                    parent_id = event["id"]
        print("\n")


# ----------------------------------------------------------------------------
# Argument parser
# ----------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="github_copilot_api",
        description="GitHub Copilot Chat API Client v2.0 — Enhanced Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
قابلیت‌ها:
  --info              نمایش اطلاعات کامل کلاینت و قابلیت‌ها
  --list-threads      لیست مکالمات
  --list-models       لیست مدل‌های LLM
  --entitlement       اطلاعات سهمیه و اشتراک
  --search-repos      جستجوی ریپازیتوری‌های کاربر
  --ask PROMPT        ارسال سوال و دریافت پاسخ
  --stream PROMPT     نمایش streaming زنده پاسخ
  --vision IMG PROMPT آپلود تصویر و سوال درباره آن
  --upload-file FILE  آپلود فایل کد/متن
  --explain PROMPT    توضیح کد/ریپو با --ref OWNER/REPO
  --show-thread ID    نمایش پیام‌های یک مکالمه
  --delete-thread ID  حذف مکالمه
  --interactive       حالت تعاملی REPL

مثال‌ها:
  %(prog)s --info
  %(prog)s --ask "یک تابع فاکتوریل بنویس"
  %(prog)s --vision photo.png "این تصویر را توصیف کن"
  %(prog)s --explain "توضیح بده" --ref octocat/Hello-World
  %(prog)s --interactive --model auto
""",
    )

    p.add_argument("--model", type=str, default="auto",
                   help="نام مدل (auto, gpt-5.5, claude-sonnet-4.6, ...) - پیش‌فرض: auto")
    p.add_argument("--no-hardcoded-token", action="store_true",
                   help="استفاده نکردن از توکن hard-coded، از مرورگر بگیر")

    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--info", action="store_true", help="نمایش اطلاعات کلاینت")
    g.add_argument("--get-token-from-browser", action="store_true",
                   help="استخراج توکن از مرورگر")
    g.add_argument("--list-threads", action="store_true", help="لیست مکالمات")
    g.add_argument("--list-models", action="store_true", help="لیست مدل‌ها")
    g.add_argument("--entitlement", action="store_true", help="اطلاعات سهمیه")
    g.add_argument("--search-repos", action="store_true", help="جستجوی ریپوهای کاربر")
    g.add_argument("--ask", type=str, metavar="PROMPT", help="ارسال سوال")
    g.add_argument("--stream", type=str, metavar="PROMPT", help="نمایش streaming")
    g.add_argument("--vision-image", type=str, metavar="PATH",
                   help="آپلود تصویر و سوال درباره آن (با --vision-prompt)")
    g.add_argument("--upload-file", type=str, metavar="PATH", help="آپلود فایل")
    g.add_argument("--explain", type=str, metavar="PROMPT",
                   help="توضیح کد/ریپو (با --ref OWNER/REPO)")
    g.add_argument("--show-thread", type=str, metavar="THREAD_ID",
                   help="نمایش پیام‌های یک مکالمه")
    g.add_argument("--delete-thread", type=str, metavar="THREAD_ID",
                   help="حذف یک مکالمه")
    g.add_argument("--interactive", action="store_true", help="حالت تعاملی")

    # Optional args
    p.add_argument("--vision-prompt", type=str, default="این تصویر را توصیف کن",
                   help="پرسش درباره تصویر (با --vision-image)")
    p.add_argument("--file-prompt", type=str,
                   default="این فایل را توضیح بده و کاربردش را بگو.",
                   help="پرسش درباره فایل (با --upload-file)")
    p.add_argument("--ref", type=str, metavar="OWNER/REPO",
                   help="ریپازیتوری برای --explain")
    p.add_argument("--limit", type=int, default=10,
                   help="حداکثر تعداد نتایج (برای --search-repos)")

    return p


def main() -> int:
    # Make stdout UTF-8 for Persian text
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.info:
            cmd_info(args)
        elif args.get_token_from_browser:
            cmd_get_token(args)
        elif args.list_threads:
            cmd_list_threads(args)
        elif args.list_models:
            cmd_list_models(args)
        elif args.entitlement:
            cmd_entitlement(args)
        elif args.search_repos:
            cmd_search_repos(args)
        elif args.ask is not None:
            cmd_ask(args)
        elif args.stream is not None:
            cmd_stream(args)
        elif args.vision_image is not None:
            cmd_vision(args)
        elif args.upload_file is not None:
            cmd_upload_file(args)
        elif args.explain is not None:
            if not args.ref:
                print("❌ --explain نیاز به --ref OWNER/REPO دارد", file=sys.stderr)
                return 1
            cmd_explain(args)
        elif args.show_thread is not None:
            cmd_show_thread(args)
        elif args.delete_thread is not None:
            cmd_delete_thread(args)
        elif args.interactive:
            cmd_interactive(args)
        return 0
    except TokenExpiredError as e:
        print(f"\n❌ {e}", file=sys.stderr)
        print("   راه‌حل: python github_copilot_api.py --get-token-from-browser",
              file=sys.stderr)
        return 2
    except CopilotAPIError as e:
        print(f"\n❌ API Error: {e}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\n\n👋 متوقف شد.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"\n❌ خطای غیرمنتظره: {type(e).__name__}: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
