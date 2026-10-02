#!/usr/bin/env python3
"""
🐺 Yuric OAuth — 从 Tide 的 tide_oauth.py 抽出来的通用版，给每个 Yuric MCP 端点加 OAuth 2.1

设计:
  - 实现 SDK 的 OAuthAuthorizationServerProvider：DCR / authorize / token / refresh / revoke。
  - 登录环节用单一密码 (OAUTH_PASSWORD) — 单用户个人服务，够用且简单。
  - Den 走静态 bearer (MCP_TOKEN)，在 load_access_token 里特批，与 OAuth token 并存。
  - clients / tokens 尽量持久化到 JSON (挂了 /data volume 时重部署后连接器不用重新登录)。
  - 没设 OAUTH_PASSWORD 时 auth_kwargs() 返回 {}，服务行为与以前完全一样 (渐进开启 / 一键回退)。

用法:
    from yuric_oauth import auth_kwargs, register_login
    mcp = FastMCP("...", host="0.0.0.0", port=PORT, **auth_kwargs("glow", "https://glow.yuric-wen.com"))
    register_login(mcp)

PKCE 由 SDK 的 token handler 自行校验 (比对 code_challenge)，本模块只负责存取。
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

log = logging.getLogger("yuric_oauth")

CODE_TTL = 300       # 授权码 5 分钟
ACCESS_TTL = 3600    # access token 1 小时
DEFAULT_SCOPES = ["mcp"]

# 登录失败限流 (CF Access 撤掉后 /login 暴露公网，防口令爆破)
LOGIN_WINDOW = 300       # 5 分钟窗口
LOGIN_MAX_FAILS = 8      # 窗口内超过就暂时锁
_login_fails: list[float] = []


def _login_locked() -> bool:
    now = time.time()
    while _login_fails and now - _login_fails[0] > LOGIN_WINDOW:
        _login_fails.pop(0)
    return len(_login_fails) >= LOGIN_MAX_FAILS


def _redirect_uri(redirect_uri: str, code: str, state: str | None) -> str:
    """把 code/state 拼到客户端 redirect_uri 上。"""
    parsed = urlparse(str(redirect_uri))
    q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    q["code"] = code
    if state is not None:
        q["state"] = state
    return urlunparse(parsed._replace(query=urlencode(q)))


class YuricOAuthProvider(OAuthAuthorizationServerProvider):
    def __init__(self, public_url: str, password: str, static_bearer: str, store_path: str = ""):
        self.public_url = public_url.rstrip("/")
        self.password = password
        self.static_bearer = static_bearer
        self.store_path = store_path
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}   # 短命，不持久化
        self.pending: dict[str, tuple[str, AuthorizationParams]] = {}  # login_id -> (client_id, params)
        self._load()

    # ---------- 持久化 (best-effort) ----------
    def _load(self):
        if not self.store_path or not os.path.exists(self.store_path):
            return
        try:
            with open(self.store_path) as f:
                data = json.load(f)
            self.clients = {k: OAuthClientInformationFull.model_validate(v)
                            for k, v in data.get("clients", {}).items()}
            self.access_tokens = {k: AccessToken.model_validate(v)
                                  for k, v in data.get("access_tokens", {}).items()}
            self.refresh_tokens = {k: RefreshToken.model_validate(v)
                                   for k, v in data.get("refresh_tokens", {}).items()}
            log.info("oauth store loaded clients=%d tokens=%d",
                     len(self.clients), len(self.access_tokens))
        except Exception as e:
            log.warning("oauth store load failed: %s", type(e).__name__)

    def _save(self):
        if not self.store_path:
            return
        try:
            tmp = self.store_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({
                    "clients": {k: json.loads(v.model_dump_json()) for k, v in self.clients.items()},
                    "access_tokens": {k: json.loads(v.model_dump_json()) for k, v in self.access_tokens.items()},
                    "refresh_tokens": {k: json.loads(v.model_dump_json()) for k, v in self.refresh_tokens.items()},
                }, f)
            os.replace(tmp, self.store_path)
        except Exception as e:
            log.warning("oauth store save failed: %s", type(e).__name__)

    # ---------- DCR ----------
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.clients[client_info.client_id] = client_info
        self._save()
        log.info("oauth client registered id=%s", client_info.client_id)

    # ---------- authorize (跳到密码登录页) ----------
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        login_id = secrets.token_urlsafe(24)
        self.pending[login_id] = (client.client_id, params)
        return f"{self.public_url}/login?lid={login_id}"

    def complete_login(self, login_id: str) -> str | None:
        """密码验证通过后由 POST /login 调用：发授权码 + 返回最终 redirect。"""
        item = self.pending.pop(login_id, None)
        if not item:
            return None
        client_id, params = item
        code = secrets.token_urlsafe(32)
        self.auth_codes[code] = AuthorizationCode(
            code=code,
            scopes=params.scopes or list(DEFAULT_SCOPES),
            expires_at=time.time() + CODE_TTL,
            client_id=client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
        )
        log.info("oauth login ok client=%s", client_id)
        return _redirect_uri(str(params.redirect_uri), code, params.state)

    # ---------- 授权码 → token ----------
    async def load_authorization_code(self, client, authorization_code: str):
        ac = self.auth_codes.get(authorization_code)
        if ac and ac.client_id == client.client_id and ac.expires_at > time.time():
            return ac
        return None

    async def exchange_authorization_code(self, client, authorization_code) -> OAuthToken:
        self.auth_codes.pop(authorization_code.code, None)  # 一次性
        return self._issue(client.client_id, authorization_code.scopes, authorization_code.resource)

    # ---------- refresh ----------
    async def load_refresh_token(self, client, refresh_token: str):
        rt = self.refresh_tokens.get(refresh_token)
        if rt and rt.client_id == client.client_id:
            return rt
        return None

    async def exchange_refresh_token(self, client, refresh_token, scopes) -> OAuthToken:
        self.refresh_tokens.pop(refresh_token.token, None)  # 轮换
        return self._issue(client.client_id, scopes or refresh_token.scopes, None)

    def _issue(self, client_id: str, scopes: list[str], resource) -> OAuthToken:
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        self.access_tokens[access] = AccessToken(
            token=access, client_id=client_id, scopes=scopes,
            expires_at=int(time.time() + ACCESS_TTL), resource=resource)
        self.refresh_tokens[refresh] = RefreshToken(
            token=refresh, client_id=client_id, scopes=scopes)
        self._save()
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=ACCESS_TTL,
                          scope=" ".join(scopes) or None, refresh_token=refresh)

    # ---------- 校验 (含 Den 静态 bearer) ----------
    async def load_access_token(self, token: str):
        if self.static_bearer and hmac.compare_digest(token, self.static_bearer):
            return AccessToken(token=token, client_id="den-static", scopes=list(DEFAULT_SCOPES), expires_at=None)
        at = self.access_tokens.get(token)
        if at and (at.expires_at is None or at.expires_at > time.time()):
            return at
        if at:  # 过期清理
            self.access_tokens.pop(token, None)
        return None

    async def revoke_token(self, token) -> None:
        self.access_tokens.pop(token.token, None)
        self.refresh_tokens.pop(token.token, None)
        self._save()


# ============================================================
# 登录页路由 (密码) — 挂到 Starlette app 上
# ============================================================

_LOGIN_HTML = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>🐺 Yuric's {name}</title><style>
body{{background:#0e1726;color:#e7eefc;font-family:-apple-system,system-ui,sans-serif;
display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}}
.card{{background:#16233a;padding:32px 28px;border-radius:18px;width:300px;
box-shadow:0 8px 40px #0008;text-align:center}}
h1{{font-size:20px;margin:0 0 4px}} p{{color:#8aa0c4;font-size:13px;margin:0 0 20px}}
input{{width:100%;box-sizing:border-box;padding:12px;border-radius:10px;border:1px solid #2c3e5e;
background:#0e1726;color:#e7eefc;font-size:15px;margin-bottom:12px}}
button{{width:100%;padding:12px;border:0;border-radius:10px;background:#4f7fff;color:#fff;
font-size:15px;font-weight:600;cursor:pointer}}
.err{{color:#ff7a85;font-size:13px;margin-bottom:10px}}</style></head>
<body><form class=card method=post action=/login>
<h1>🐺 Yuric's {name}</h1><p>Authorize this connector</p>
{err}<input type=hidden name=lid value="{lid}">
<input type=password name=password placeholder="Passcode" autofocus autocomplete=current-password>
<button type=submit>Authorize</button></form></body></html>"""


def make_login_routes(provider: YuricOAuthProvider, name: str) -> list[Route]:
    def page(lid: str, err: str = "") -> str:
        return _LOGIN_HTML.format(lid=lid, err=err, name=name)

    async def login_get(request: Request):
        return HTMLResponse(page(request.query_params.get("lid", "")))

    async def login_post(request: Request):
        if _login_locked():
            log.warning("oauth login throttled")
            return HTMLResponse(page("", '<div class=err>Too many attempts — wait a few minutes.</div>'),
                                status_code=429)
        form = await request.form()
        lid = str(form.get("lid", ""))
        password = str(form.get("password", ""))
        if not lid or lid not in provider.pending:
            return HTMLResponse(page("", '<div class=err>Session expired — reconnect.</div>'), status_code=400)
        if not provider.password or not hmac.compare_digest(password, provider.password):
            _login_fails.append(time.time())
            log.warning("oauth login bad password")
            return HTMLResponse(page(lid, '<div class=err>Wrong passcode.</div>'), status_code=401)
        target = provider.complete_login(lid)
        if not target:
            return HTMLResponse(page("", '<div class=err>Session expired — reconnect.</div>'), status_code=400)
        return RedirectResponse(target, status_code=302)

    return [
        Route("/login", login_get, methods=["GET"]),
        Route("/login", login_post, methods=["POST"]),
    ]


# ============================================================
# 接到 FastMCP 上 (env 驱动；没设 OAUTH_PASSWORD 就什么都不做)
# ============================================================

_provider: YuricOAuthProvider | None = None
_name = ""


def auth_kwargs(service: str, default_public_url: str) -> dict:
    """返回要展开进 FastMCP(...) 的 auth 参数。OAUTH_PASSWORD 没设 → {}。"""
    global _provider, _name
    password = os.environ.get("OAUTH_PASSWORD", "")
    if not password:
        log.warning("%s: OAUTH_PASSWORD 未设置 — /sse 无鉴权 (公开)", service)
        return {}
    from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions

    public_url = os.environ.get("PUBLIC_URL", default_public_url).rstrip("/")
    store = os.environ.get("OAUTH_STORE", "/data/oauth.json" if os.path.isdir("/data") else "")
    static_bearer = os.environ.get("MCP_TOKEN", "")
    if not static_bearer:
        log.warning("%s: MCP_TOKEN 未设置 — Den 的静态 bearer 会被拒", service)
    _name = service.capitalize()
    _provider = YuricOAuthProvider(public_url, password, static_bearer, store)
    log.info("%s: OAuth on (issuer=%s store=%s)", service, public_url, store or "memory")
    return {
        "auth_server_provider": _provider,
        "auth": AuthSettings(
            issuer_url=public_url,
            resource_server_url=public_url,
            required_scopes=[],  # 任何有效 token 即可调用工具，不卡 scope
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=DEFAULT_SCOPES, default_scopes=DEFAULT_SCOPES),
            revocation_options=RevocationOptions(enabled=True),
        ),
    }


def register_login(mcp) -> None:
    """OAuth 开着时把 /login 密码页挂到 FastMCP 的 custom routes 上。"""
    if _provider is None:
        return
    for r in make_login_routes(_provider, _name):
        mcp.custom_route(r.path, methods=list(r.methods - {"HEAD"}))(r.endpoint)
