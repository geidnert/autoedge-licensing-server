from __future__ import annotations

import html
import json
import os
import sys
import time
from http import HTTPStatus
from typing import Any, Callable
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

from .config import Settings
from .db import Database, apply_migrations
from .security import (
    parse_cookie,
    sha256_hex,
    sign_value,
    unsign_value,
    verify_bearer,
    verify_standard_webhook,
)
from .service import LicensingService, slugify


HeaderList = list[tuple[str, str]]
StartResponse = Callable[[str, HeaderList], None]


class RateLimiter:
    def __init__(self, limit_per_minute: int):
        self.limit_per_minute = limit_per_minute
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        window_start = now - 60
        hits = [value for value in self._hits.get(key, []) if value >= window_start]
        if len(hits) >= self.limit_per_minute:
            self._hits[key] = hits
            return False
        hits.append(now)
        self._hits[key] = hits
        return True


class Request:
    def __init__(self, environ: dict[str, Any]):
        self.environ = environ
        self.method = environ.get("REQUEST_METHOD", "GET").upper()
        self.path = environ.get("PATH_INFO", "/")
        self.query = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
        self.ip = environ.get("HTTP_X_FORWARDED_FOR", environ.get("REMOTE_ADDR", "")).split(",")[0].strip()
        self.user_agent = environ.get("HTTP_USER_AGENT")
        self.headers = self._headers(environ)
        length = int(environ.get("CONTENT_LENGTH") or 0)
        self.body = environ["wsgi.input"].read(length) if length > 0 else b""

    def json(self) -> dict[str, Any]:
        if not self.body:
            return {}
        value = json.loads(self.body.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object.")
        return value

    def form(self) -> dict[str, str]:
        parsed = parse_qs(self.body.decode("utf-8"), keep_blank_values=True)
        return {key: values[-1] if values else "" for key, values in parsed.items()}

    def query_value(self, key: str, default: str = "") -> str:
        values = self.query.get(key)
        return values[-1] if values else default

    @staticmethod
    def _headers(environ: dict[str, Any]) -> dict[str, str]:
        headers: dict[str, str] = {}
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                name = key[5:].replace("_", "-").lower()
                headers[name] = value
        if "CONTENT_TYPE" in environ:
            headers["content-type"] = environ["CONTENT_TYPE"]
        return headers


class Response:
    def __init__(self, status: HTTPStatus, body: bytes, headers: HeaderList | None = None):
        self.status = status
        self.body = body
        self.headers = headers or []

    def __call__(self, start_response: StartResponse) -> list[bytes]:
        headers = [("Content-Length", str(len(self.body))), *self.headers]
        start_response(f"{self.status.value} {self.status.phrase}", headers)
        return [self.body]


class AutoEdgeApp:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.database = Database(settings.database_path)
        apply_migrations(self.database)
        self.service = LicensingService(self.database)
        self.rate_limiter = RateLimiter(settings.rate_limit_per_minute)

    def __call__(self, environ: dict[str, Any], start_response: StartResponse) -> list[bytes]:
        request = Request(environ)
        try:
            response = self.route(request)
        except Exception as exc:
            response = self.error_response(exc)
        return response(start_response)

    def route(self, request: Request) -> Response:
        if request.path == "/healthz":
            return json_response({"status": "ok"})
        if request.path in {"/api/trader/license/check", "/api/trader/license/activate"} and request.method == "POST":
            return self.trader_license_check(request)
        if request.path == "/api/whop/entitlements" and request.method == "POST":
            return self.whop_entitlement_update(request)

        if request.path == "/admin/login":
            return self.admin_login(request)
        if request.path == "/admin/logout":
            return self.admin_logout(request)
        if request.path == "/admin":
            return redirect("/admin/customers")
        if request.path == "/admin/password":
            return self.with_admin(request, self.admin_password)
        if request.path == "/admin/customers":
            return self.with_admin(request, self.admin_customers)
        if request.path == "/admin/products":
            return self.with_admin(request, self.admin_products)
        if request.path == "/admin/packages":
            return self.with_admin(request, self.admin_packages)
        if request.path.startswith("/admin/customers/"):
            return self.with_admin(request, self.admin_customer_detail)
        if request.path.startswith("/admin/devices/"):
            return self.with_admin(request, self.admin_device_action)
        return text_response(HTTPStatus.NOT_FOUND, "Not found")

    def trader_license_check(self, request: Request) -> Response:
        if not self.rate_limiter.allow(f"license:{request.ip}"):
            return json_response({"status": "rate_limited", "message": "Too many license checks."}, HTTPStatus.TOO_MANY_REQUESTS)
        payload = request.json()
        response = self.service.check_license(
            license_key=payload.get("license_key"),
            email=payload.get("email"),
            customer_id=payload.get("customer_id"),
            whop_user_id=payload.get("whop_user_id"),
            machine_fingerprint=payload.get("machine_fingerprint") or "",
            app_version=payload.get("app_version"),
            ip_address=request.ip,
            user_agent=request.user_agent,
            check_interval_seconds=self.settings.license_check_interval_seconds,
            grace_period_seconds=self.settings.grace_period_seconds,
        )
        return json_response(response)

    def whop_entitlement_update(self, request: Request) -> Response:
        if not self.rate_limiter.allow(f"whop:{request.ip}"):
            return json_response({"status": "rate_limited"}, HTTPStatus.TOO_MANY_REQUESTS)
        signature_valid = False
        signature_reason = "not checked"
        if self.settings.whop_webhook_secret and request.headers.get("webhook-signature"):
            signature_valid, signature_reason = verify_standard_webhook(
                request.body,
                request.headers,
                self.settings.whop_webhook_secret,
            )
        bearer_valid = verify_bearer(request.headers, self.settings.whop_bearer_token)
        if not signature_valid and not bearer_valid:
            return json_response({"status": "unauthorized", "message": signature_reason}, HTTPStatus.UNAUTHORIZED)
        payload = request.json()
        webhook_id = request.headers.get("webhook-id") or str(payload.get("id") or payload.get("event_id") or sha256_hex(request.body.decode("utf-8")))
        result = self.service.process_whop_event(payload, webhook_id, signature_valid=signature_valid or bearer_valid, ip_address=request.ip)
        return json_response(result)

    def admin_login(self, request: Request) -> Response:
        if request.method == "GET":
            notice = "Password changed. Sign in again." if request.query_value("password_changed") == "1" else None
            return html_response(self.page("Sign in", login_form(notice=notice)))
        if request.method != "POST":
            return text_response(HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed")
        form = request.form()
        result = self.service.authenticate_admin(
            form.get("username", ""),
            form.get("password", ""),
            session_hours=self.settings.session_hours,
            ip_address=request.ip,
            user_agent=request.user_agent,
        )
        if result is None:
            return html_response(self.page("Sign in", login_form("Invalid username or password.")), HTTPStatus.UNAUTHORIZED)
        _, token = result
        cookie = self.session_cookie(token)
        return redirect("/admin/customers", [("Set-Cookie", cookie)])

    def admin_logout(self, request: Request) -> Response:
        token = self.session_token(request)
        admin = self.service.admin_from_session(token)
        if token:
            self.service.revoke_session(token, admin["id"] if admin else None)
        return redirect("/admin/login", [("Set-Cookie", self.expired_session_cookie())])

    def with_admin(self, request: Request, handler: Callable[[Request, dict[str, Any]], Response]) -> Response:
        token = self.session_token(request)
        admin = self.service.admin_from_session(token)
        if admin is None:
            return redirect("/admin/login")
        if request.method == "POST" and request.form().get("csrf") != self.csrf_token(token or ""):
            return text_response(HTTPStatus.FORBIDDEN, "Invalid CSRF token.")
        return handler(request, admin)

    def admin_customers(self, request: Request, admin: dict[str, Any]) -> Response:
        if request.method == "POST":
            form = request.form()
            created = self.service.create_or_update_customer(
                email=form.get("email"),
                name=form.get("name"),
                whop_user_id=form.get("whop_user_id"),
                whop_member_id=form.get("whop_member_id"),
                actor_type="admin",
                actor_id=admin["id"],
                ip_address=request.ip,
            )
            suffix = f"?created_key={html.escape(created.license_key or '')}" if created.license_key else ""
            return redirect(f"/admin/customers/{created.customer['id']}{suffix}")
        query = request.query_value("q")
        customers = self.service.search_customers(query)
        csrf = self.csrf_token(self.session_token(request) or "")
        body = customer_search_page(customers, query, csrf)
        return html_response(self.page("Customers", body, admin))

    def admin_products(self, request: Request, admin: dict[str, Any]) -> Response:
        csrf = self.csrf_token(self.session_token(request) or "")
        if request.method == "POST":
            form = request.form()
            product_id = form.get("product_id", "").strip()
            name = form.get("name", "")
            internal_slug = form.get("slug") or name
            internal_feature_id = form.get("feature_id") or f"strategy.{slugify(internal_slug)}.runtime"
            if product_id:
                existing = self.service.get_product(product_id)
                self.service.update_product(
                    product_id=product_id,
                    slug=internal_slug,
                    name=name,
                    feature_id=internal_feature_id,
                    whop_product_id=existing.get("whop_product_id") if existing else None,
                    is_active=form.get("is_active") == "on",
                    actor_id=admin["id"],
                    ip_address=request.ip,
                )
            else:
                self.service.upsert_product(
                    slug=internal_slug,
                    name=name,
                    feature_id=internal_feature_id,
                    whop_product_id=form.get("whop_product_id") or None,
                    is_active=form.get("is_active") == "on",
                    actor_id=admin["id"],
                    ip_address=request.ip,
                )
            return redirect("/admin/products")
        products = self.service.list_products()
        edit_id = request.query_value("edit")
        selected_product = self.service.get_product(edit_id) if edit_id else None
        return html_response(self.page("Products", products_page(products, csrf, selected_product), admin))

    def admin_packages(self, request: Request, admin: dict[str, Any]) -> Response:
        csrf = self.csrf_token(self.session_token(request) or "")
        products = self.service.list_products()
        if request.method == "POST":
            form = request.form()
            default_days = parse_optional_int(form.get("default_days"))
            grants: list[dict[str, Any]] = []
            for product in products:
                product_id = product["id"]
                if form.get(f"grant_{product_id}") != "on":
                    continue
                grants.append(
                    {
                        "product_id": product_id,
                        "days": parse_optional_int(form.get(f"days_{product_id}")),
                        "legacy_nt_product_id": form.get(f"legacy_{product_id}") or None,
                    }
                )
            self.service.upsert_whop_package(
                package_id=form.get("package_id") or None,
                whop_id=form.get("whop_id", ""),
                whop_id_type=form.get("whop_id_type", "plan"),
                name=form.get("name", ""),
                default_days=default_days,
                is_active=form.get("is_active") == "on",
                is_ignored=form.get("is_ignored") == "on",
                grants=grants,
                actor_id=admin["id"],
                ip_address=request.ip,
            )
            return redirect("/admin/packages")
        packages = self.service.list_whop_packages()
        edit_id = request.query_value("edit")
        selected_package = self.service.get_whop_package(edit_id) if edit_id else None
        return html_response(self.page("Whop Packages", packages_page(packages, products, csrf, selected_package), admin))

    def admin_password(self, request: Request, admin: dict[str, Any]) -> Response:
        csrf = self.csrf_token(self.session_token(request) or "")
        if request.method == "GET":
            return html_response(self.page("Change Password", password_page(csrf), admin))
        if request.method != "POST":
            return text_response(HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed")
        form = request.form()
        new_password = form.get("new_password", "")
        if new_password != form.get("confirm_password", ""):
            return html_response(
                self.page("Change Password", password_page(csrf, "New password and confirmation do not match."), admin),
                HTTPStatus.BAD_REQUEST,
            )
        changed, message = self.service.change_admin_password(
            admin_id=admin["id"],
            current_password=form.get("current_password", ""),
            new_password=new_password,
            ip_address=request.ip,
        )
        if not changed:
            return html_response(self.page("Change Password", password_page(csrf, message), admin), HTTPStatus.BAD_REQUEST)
        return redirect("/admin/login?password_changed=1", [("Set-Cookie", self.expired_session_cookie())])

    def admin_customer_detail(self, request: Request, admin: dict[str, Any]) -> Response:
        parts = [part for part in request.path.split("/") if part]
        if len(parts) < 3:
            return text_response(HTTPStatus.NOT_FOUND, "Not found")
        customer_id = parts[2]
        if len(parts) == 4 and parts[3] == "entitlements" and request.method == "POST":
            form = request.form()
            self.service.manual_set_entitlement(
                customer_id=customer_id,
                product_id=form.get("product_id", ""),
                status=form.get("status", ""),
                expires_at=form.get("expires_at") or None,
                reason=form.get("reason") or None,
                actor_id=admin["id"],
                ip_address=request.ip,
            )
            return redirect(f"/admin/customers/{customer_id}")
        detail = self.service.customer_detail(customer_id)
        if detail is None:
            return text_response(HTTPStatus.NOT_FOUND, "Customer not found")
        products = self.service.list_products(include_inactive=False)
        csrf = self.csrf_token(self.session_token(request) or "")
        created_key = request.query_value("created_key")
        body = customer_detail_page(detail, products, csrf, created_key)
        return html_response(self.page("Customer", body, admin))

    def admin_device_action(self, request: Request, admin: dict[str, Any]) -> Response:
        if request.method != "POST":
            return text_response(HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed")
        parts = [part for part in request.path.split("/") if part]
        if len(parts) != 4 or parts[3] not in {"block", "unblock"}:
            return text_response(HTTPStatus.NOT_FOUND, "Not found")
        form = request.form()
        self.service.set_device_blocked(
            device_id=parts[2],
            is_blocked=parts[3] == "block",
            note=form.get("note") or None,
            actor_id=admin["id"],
            ip_address=request.ip,
        )
        return redirect(form.get("return_to") or "/admin/customers")

    def session_token(self, request: Request) -> str | None:
        cookies = parse_cookie(request.headers.get("cookie"))
        signed = cookies.get("autoedge_admin")
        return unsign_value(self.settings.admin_cookie_secret, signed) if signed else None

    def session_cookie(self, token: str) -> str:
        value = sign_value(self.settings.admin_cookie_secret, token)
        cookie = f"autoedge_admin={value}; Path=/admin; Max-Age={self.settings.session_hours * 3600}; HttpOnly; SameSite=Strict"
        if self.settings.cookie_secure:
            cookie += "; Secure"
        return cookie

    def expired_session_cookie(self) -> str:
        cookie = "autoedge_admin=; Path=/admin; Max-Age=0; HttpOnly; SameSite=Strict"
        if self.settings.cookie_secure:
            cookie += "; Secure"
        return cookie

    def csrf_token(self, session_token: str) -> str:
        return sha256_hex(f"{session_token}:{self.settings.admin_cookie_secret}")

    def page(self, title: str, body: str, admin: dict[str, Any] | None = None) -> str:
        nav = ""
        if admin:
            nav = """
            <nav>
              <a href="/admin/customers">Customers</a>
              <a href="/admin/products">Products</a>
              <a href="/admin/packages">Whop Packages</a>
              <span class="spacer"></span>
              <span>{username}</span>
              <a href="/admin/password">Change password</a>
              <a href="/admin/logout">Sign out</a>
            </nav>
            """.format(username=e(admin["username"]))
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{e(title)} · AutoEdge Licensing</title>
  <style>{STYLE}</style>
</head>
<body>
  {nav}
  <main>{body}</main>
</body>
</html>"""

    def error_response(self, exc: Exception) -> Response:
        if isinstance(exc, ValueError):
            return text_response(HTTPStatus.BAD_REQUEST, str(exc))
        return text_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error")


def e(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def display_product_name(value: str | None) -> str:
    if not value:
        return ""
    if value.endswith(" Runtime"):
        return value[: -len(" Runtime")]
    return value


def format_bool(value: Any) -> str:
    return "yes" if value else "no"


def format_json(value: str | None) -> str:
    if not value:
        return ""
    try:
        return json.dumps(json.loads(value), indent=2, sort_keys=True)
    except json.JSONDecodeError:
        return value


def parse_optional_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    return int(value)


def json_response(data: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> Response:
    body = json.dumps(data, sort_keys=True).encode("utf-8")
    return Response(status, body, [("Content-Type", "application/json; charset=utf-8")])


def text_response(status: HTTPStatus, text: str) -> Response:
    return Response(status, text.encode("utf-8"), [("Content-Type", "text/plain; charset=utf-8")])


def html_response(html_body: str, status: HTTPStatus = HTTPStatus.OK) -> Response:
    return Response(status, html_body.encode("utf-8"), [("Content-Type", "text/html; charset=utf-8")])


def redirect(location: str, headers: HeaderList | None = None) -> Response:
    return Response(HTTPStatus.SEE_OTHER, b"", [("Location", location), *(headers or [])])


def login_form(error: str | None = None, notice: str | None = None) -> str:
    message = f'<p class="error">{e(error)}</p>' if error else ""
    notice_message = f'<p class="notice">{e(notice)}</p>' if notice else ""
    return f"""
    <section class="auth">
      <h1>AutoEdge Licensing</h1>
      {notice_message}
      {message}
      <form method="post" action="/admin/login">
        <label>Username <input name="username" autocomplete="username" required></label>
        <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
        <button type="submit">Sign in</button>
      </form>
    </section>
    """


def password_page(csrf: str, error: str | None = None) -> str:
    message = f'<p class="error">{e(error)}</p>' if error else ""
    return f"""
    <header class="title-row">
      <div>
        <h1>Change Password</h1>
        <p>Changing the password signs out all active admin sessions.</p>
      </div>
    </header>
    <section class="panel narrow-panel">
      {message}
      <form class="stack-form" method="post" action="/admin/password">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <label>Current password <input name="current_password" type="password" autocomplete="current-password" required></label>
        <label>New password <input name="new_password" type="password" autocomplete="new-password" minlength="12" required></label>
        <label>Confirm new password <input name="confirm_password" type="password" autocomplete="new-password" minlength="12" required></label>
        <button type="submit">Change password</button>
      </form>
    </section>
    """


def customer_search_page(customers: list[dict[str, Any]], query: str, csrf: str) -> str:
    rows = "\n".join(
        f"""
        <tr>
          <td><a href="/admin/customers/{e(customer['id'])}">{e(customer.get('email') or '(no email)')}</a><small>{e(customer.get('name'))}</small></td>
          <td>{e(customer.get('whop_user_id'))}<small>member {e(customer.get('whop_member_id'))}</small></td>
          <td>{e(customer.get('license_key_last4'))}</td>
          <td>{e(customer.get('entitlement_count'))}</td>
          <td>{e(customer.get('device_count'))}</td>
          <td>{e(customer.get('updated_at'))}</td>
        </tr>
        """
        for customer in customers
    )
    return f"""
    <header class="title-row">
      <div>
        <h1>Customers</h1>
        <p>Search by email, Whop id, member id, name, or internal customer id.</p>
      </div>
    </header>
    <form class="search" method="get">
      <input name="q" value="{e(query)}" placeholder="Search customers">
      <button type="submit">Search</button>
    </form>
    <section class="panel">
      <h2>Create customer</h2>
      <form class="grid-form" method="post">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <label>Email <input name="email" type="email"></label>
        <label>Name <input name="name"></label>
        <label>Whop user id <input name="whop_user_id"></label>
        <label>Whop member id <input name="whop_member_id"></label>
        <button type="submit">Create</button>
      </form>
    </section>
    <section class="panel">
      <table>
        <thead><tr><th>Customer</th><th>Whop IDs</th><th>Key</th><th>Entitlements</th><th>Devices</th><th>Updated</th></tr></thead>
        <tbody>{rows or '<tr><td colspan="6">No customers found.</td></tr>'}</tbody>
      </table>
    </section>
    """


def products_page(products: list[dict[str, Any]], csrf: str, selected_product: dict[str, Any] | None = None) -> str:
    selected = selected_product or {}
    is_editing = selected_product is not None
    form_title = "Edit product" if is_editing else "Add or update product"
    button_text = "Save changes" if is_editing else "Save product"
    active_checked = "checked" if selected.get("is_active", 1) else ""
    cancel_link = '<a class="button secondary" href="/admin/products">Cancel</a>' if is_editing else ""
    selected_name = display_product_name(selected.get("name"))
    rows = "\n".join(
        f"""
        <tr>
          <td>{e(display_product_name(product.get('name')))}</td>
          <td>{format_bool(product.get('is_active'))}</td>
          <td>{e(product.get('updated_at'))}</td>
          <td><a class="button small" href="/admin/products?edit={e(product['id'])}">Edit</a></td>
        </tr>
        """
        for product in products
    )
    return f"""
    <header class="title-row">
      <div>
        <h1>Products</h1>
        <p>Products define Trader strategies. Whop plan mappings are managed on the Whop Packages page.</p>
      </div>
    </header>
    <section class="panel">
      <h2>{form_title}</h2>
      <form class="grid-form" method="post">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <input type="hidden" name="product_id" value="{e(selected.get('id'))}">
        <input type="hidden" name="slug" value="{e(selected.get('slug'))}">
        <input type="hidden" name="feature_id" value="{e(selected.get('feature_id'))}">
        <label>Strategy <input name="name" required placeholder="DUO" value="{e(selected_name)}"></label>
        <label class="checkbox"><input name="is_active" type="checkbox" {active_checked}> Active</label>
        <button type="submit">{button_text}</button>
        {cancel_link}
      </form>
    </section>
    <section class="panel">
      <table>
        <thead><tr><th>Strategy</th><th>Active</th><th>Updated</th><th></th></tr></thead>
        <tbody>{rows or '<tr><td colspan="4">No products configured.</td></tr>'}</tbody>
      </table>
    </section>
    """


def packages_page(
    packages: list[dict[str, Any]],
    products: list[dict[str, Any]],
    csrf: str,
    selected_package: dict[str, Any] | None = None,
) -> str:
    selected = selected_package or {}
    is_editing = selected_package is not None
    selected_grants = {grant["product_id"]: grant for grant in selected.get("grants", [])}
    type_options = "\n".join(
        f'<option value="{value}" {"selected" if selected.get("whop_id_type", "plan") == value else ""}>{label}</option>'
        for value, label in (("plan", "Plan"), ("product", "Product"), ("unknown", "Unknown"))
    )
    active_checked = "checked" if selected.get("is_active", 1) else ""
    ignored_checked = "checked" if selected.get("is_ignored", 0) else ""
    form_title = "Edit Whop package" if is_editing else "Add Whop package"
    button_text = "Save changes" if is_editing else "Save package"
    cancel_link = '<a class="button secondary" href="/admin/packages">Cancel</a>' if is_editing else ""

    grant_rows = "\n".join(
        f"""
        <tr>
          <td>
            <label class="checkbox">
              <input name="grant_{e(product['id'])}" type="checkbox" {'checked' if product['id'] in selected_grants else ''}>
              {e(display_product_name(product.get('name')))}
            </label>
          </td>
          <td><input name="days_{e(product['id'])}" type="number" min="0" placeholder="default" value="{e(selected_grants.get(product['id'], {}).get('days'))}"></td>
          <td><input name="legacy_{e(product['id'])}" placeholder="204" value="{e(selected_grants.get(product['id'], {}).get('legacy_nt_product_id'))}"></td>
        </tr>
        """
        for product in products
    )

    def grant_summary(package: dict[str, Any]) -> str:
        grants = package.get("grants", [])
        if not grants:
            return '<span class="muted">No grants</span>'
        parts = []
        for grant in grants:
            days = grant.get("days") if grant.get("days") is not None else package.get("default_days")
            label = f"{display_product_name(grant.get('product_name'))} {days}d" if days is not None else display_product_name(grant.get("product_name"))
            legacy = f"<small>NT {e(grant.get('legacy_nt_product_id'))}</small>" if grant.get("legacy_nt_product_id") else ""
            parts.append(f"<span>{e(label)}{legacy}</span>")
        return '<div class="grant-list">' + "".join(parts) + "</div>"

    rows = "\n".join(
        f"""
        <tr>
          <td><strong>{e(package.get('name'))}</strong><small>{e(package.get('whop_id'))}</small></td>
          <td>{e(package.get('whop_id_type'))}</td>
          <td>{e(package.get('default_days'))}</td>
          <td>{grant_summary(package)}</td>
          <td>{format_bool(package.get('is_ignored'))}</td>
          <td>{format_bool(package.get('is_active'))}</td>
          <td><a class="button small" href="/admin/packages?edit={e(package['id'])}">Edit</a></td>
        </tr>
        """
        for package in packages
    )
    return f"""
    <header class="title-row">
      <div>
        <h1>Whop Packages</h1>
        <p>Map Whop plans or products to Trader strategy access and day grants.</p>
      </div>
    </header>
    <section class="panel">
      <h2>{form_title}</h2>
      <form method="post">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <input type="hidden" name="package_id" value="{e(selected.get('id'))}">
        <div class="grid-form package-form">
          <label>Name <input name="name" required placeholder="DUO 30 days" value="{e(selected.get('name'))}"></label>
          <label>Whop id <input name="whop_id" required placeholder="plan_..." value="{e(selected.get('whop_id'))}"></label>
          <label>Type <select name="whop_id_type">{type_options}</select></label>
          <label>Default days <input name="default_days" type="number" min="0" placeholder="30" value="{e(selected.get('default_days'))}"></label>
          <label class="checkbox"><input name="is_active" type="checkbox" {active_checked}> Active</label>
          <label class="checkbox"><input name="is_ignored" type="checkbox" {ignored_checked}> Non-license</label>
        </div>
        <table class="grant-table">
          <thead><tr><th>Strategy</th><th>Days</th><th>Legacy NT product id</th></tr></thead>
          <tbody>{grant_rows or '<tr><td colspan="3">No strategies configured.</td></tr>'}</tbody>
        </table>
        <div class="form-actions">
          <button type="submit">{button_text}</button>
          {cancel_link}
        </div>
      </form>
    </section>
    <section class="panel">
      <table>
        <thead><tr><th>Package</th><th>Type</th><th>Default days</th><th>Grants</th><th>Ignored</th><th>Active</th><th></th></tr></thead>
        <tbody>{rows or '<tr><td colspan="7">No Whop packages configured.</td></tr>'}</tbody>
      </table>
    </section>
    """


def customer_detail_page(detail: dict[str, Any], products: list[dict[str, Any]], csrf: str, created_key: str) -> str:
    customer = detail["customer"]
    product_options = "\n".join(f'<option value="{e(product["id"])}">{e(display_product_name(product.get("name")))}</option>' for product in products)
    key_notice = f'<p class="notice">New license key: <code>{e(created_key)}</code>. Store it now; only the last four characters are retained.</p>' if created_key else ""
    entitlements = "\n".join(
        f"""
        <tr>
          <td>{e(display_product_name(entitlement.get('product_name')))}</td>
          <td><strong class="status {e(entitlement['status'])}">{e(entitlement['status'])}</strong><small>{e(entitlement['source'])}</small></td>
          <td>{e(entitlement.get('expires_at'))}</td>
          <td>{e(entitlement.get('manual_reason'))}</td>
          <td>{e(entitlement.get('updated_at'))}</td>
        </tr>
        """
        for entitlement in detail["entitlements"]
    )
    subscriptions = "\n".join(
        f"""
        <tr>
          <td>{e(subscription.get('whop_membership_id'))}</td>
          <td>{e(subscription.get('status'))}<small>{e(subscription.get('raw_status'))}</small></td>
          <td>{e(subscription.get('current_period_end'))}</td>
          <td>{e(subscription.get('updated_at'))}</td>
        </tr>
        """
        for subscription in detail["subscriptions"]
    )
    devices = "\n".join(
        f"""
        <tr>
          <td>{e(device.get('fingerprint_last8'))}<small>{e(device.get('id'))}</small></td>
          <td>{e(device.get('app_version'))}</td>
          <td>{e(device.get('ip_last'))}</td>
          <td>{e(device.get('last_seen_at'))}</td>
          <td>{format_bool(device.get('is_blocked'))}</td>
          <td>
            <form method="post" action="/admin/devices/{e(device['id'])}/{'unblock' if device.get('is_blocked') else 'block'}">
              <input type="hidden" name="csrf" value="{e(csrf)}">
              <input type="hidden" name="return_to" value="/admin/customers/{e(customer['id'])}">
              <button type="submit">{'Unblock' if device.get('is_blocked') else 'Block'}</button>
            </form>
          </td>
        </tr>
        """
        for device in detail["devices"]
    )
    checks = "\n".join(
        f"""
        <tr>
          <td>{e(check.get('created_at'))}</td>
          <td><strong class="status {e(check.get('status'))}">{e(check.get('status'))}</strong></td>
          <td>{e(check.get('app_version'))}</td>
          <td>{e(check.get('ip_address'))}</td>
          <td><details><summary>response</summary><pre>{e(format_json(check.get('response_json')))}</pre></details></td>
        </tr>
        """
        for check in detail["checks"]
    )
    audit_rows = "\n".join(
        f"""
        <tr>
          <td>{e(audit.get('created_at'))}</td>
          <td>{e(audit.get('actor_type'))}</td>
          <td>{e(audit.get('action'))}</td>
          <td><pre>{e(format_json(audit.get('details_json')))}</pre></td>
        </tr>
        """
        for audit in detail["audit"]
    )
    return f"""
    <header class="title-row">
      <div>
        <h1>{e(customer.get('email') or customer['id'])}</h1>
        <p>{e(customer.get('name'))}</p>
      </div>
      <a class="button" href="/admin/customers">Back</a>
    </header>
    {key_notice}
    <section class="facts">
      <div><span>Customer ID</span><code>{e(customer['id'])}</code></div>
      <div><span>Whop user</span><code>{e(customer.get('whop_user_id'))}</code></div>
      <div><span>Whop member</span><code>{e(customer.get('whop_member_id'))}</code></div>
      <div><span>License key</span><code>•••• {e(customer.get('license_key_last4'))}</code></div>
    </section>
    <section class="panel">
      <h2>Manual strategy access</h2>
      <form class="grid-form" method="post" action="/admin/customers/{e(customer['id'])}/entitlements">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <label>Strategy <select name="product_id" required>{product_options}</select></label>
        <label>Status
          <select name="status">
            <option value="active">active</option>
            <option value="trialing">trialing</option>
            <option value="expired">expired</option>
            <option value="revoked">revoked</option>
            <option value="suspended">suspended</option>
          </select>
        </label>
        <label>Expiry UTC <input name="expires_at" placeholder="2026-12-31T23:59:59Z"></label>
        <label>Reason <input name="reason"></label>
        <button type="submit">Apply</button>
      </form>
    </section>
    <section class="panel">
      <h2>Entitlements</h2>
      <table><thead><tr><th>Strategy</th><th>Status</th><th>Expiry</th><th>Reason</th><th>Updated</th></tr></thead><tbody>{entitlements or '<tr><td colspan="5">No entitlements.</td></tr>'}</tbody></table>
    </section>
    <section class="panel">
      <h2>Subscriptions</h2>
      <table><thead><tr><th>Whop membership</th><th>Status</th><th>Period end</th><th>Updated</th></tr></thead><tbody>{subscriptions or '<tr><td colspan="4">No subscriptions.</td></tr>'}</tbody></table>
    </section>
    <section class="panel">
      <h2>Devices</h2>
      <table><thead><tr><th>Fingerprint</th><th>App</th><th>IP</th><th>Last seen</th><th>Blocked</th><th></th></tr></thead><tbody>{devices or '<tr><td colspan="6">No devices.</td></tr>'}</tbody></table>
    </section>
    <section class="panel">
      <h2>License check-ins</h2>
      <table><thead><tr><th>Time</th><th>Status</th><th>App</th><th>IP</th><th>Response</th></tr></thead><tbody>{checks or '<tr><td colspan="5">No check-ins.</td></tr>'}</tbody></table>
    </section>
    <section class="panel">
      <h2>Audit log</h2>
      <table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>{audit_rows or '<tr><td colspan="4">No audit events.</td></tr>'}</tbody></table>
    </section>
    """


STYLE = """
:root { color-scheme: light; --bg: #f6f7f8; --panel: #ffffff; --text: #202428; --muted: #64707d; --line: #d8dee4; --accent: #136f63; --danger: #b42318; --warn: #a15c00; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 14px; }
nav { height: 52px; display: flex; align-items: center; gap: 18px; padding: 0 24px; background: #17202a; color: #fff; }
nav a { color: #fff; text-decoration: none; font-weight: 600; }
nav .spacer { flex: 1; }
main { width: min(1180px, calc(100vw - 32px)); margin: 24px auto 48px; }
h1 { margin: 0; font-size: 26px; }
h2 { margin: 0 0 16px; font-size: 18px; }
p { margin: 6px 0 0; color: var(--muted); }
a { color: #0f5d53; }
button, .button { min-height: 36px; padding: 0 14px; border: 1px solid #0f5d53; border-radius: 6px; background: #136f63; color: #fff; font-weight: 650; text-decoration: none; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; }
button:hover, .button:hover { background: #0f5d53; }
.button.secondary { background: #fff; color: #0f5d53; }
.button.secondary:hover { background: #eef9f6; }
.button.small { min-height: 30px; padding: 0 10px; font-size: 13px; }
input, select { min-height: 36px; width: 100%; padding: 7px 9px; border: 1px solid var(--line); border-radius: 6px; background: #fff; color: var(--text); }
label { display: grid; gap: 6px; color: #34404c; font-weight: 600; }
small { display: block; margin-top: 3px; color: var(--muted); font-weight: 400; }
.muted { color: var(--muted); }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
th { color: #394652; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
pre { margin: 0; max-width: 620px; overflow: auto; white-space: pre-wrap; font-size: 12px; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.auth { width: min(420px, calc(100vw - 32px)); margin: 80px auto; padding: 26px; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
.auth form { display: grid; gap: 14px; margin-top: 22px; }
.error { padding: 10px 12px; background: #fff0ef; color: var(--danger); border: 1px solid #ffd2cf; border-radius: 6px; }
.notice { padding: 12px 14px; background: #eef9f6; color: #0b4e45; border: 1px solid #b8ded6; border-radius: 6px; }
.title-row { display: flex; align-items: start; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
.search { display: flex; gap: 8px; margin-bottom: 16px; }
.search input { max-width: 520px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
.narrow-panel { max-width: 520px; }
.stack-form { display: grid; gap: 14px; }
.grid-form { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)) auto; gap: 12px; align-items: end; }
.package-form { grid-template-columns: repeat(4, minmax(0, 1fr)) repeat(2, auto); margin-bottom: 14px; }
.checkbox { min-height: 36px; display: flex; align-items: center; gap: 8px; }
.checkbox input { width: auto; min-height: auto; }
.grant-table { margin: 8px 0 14px; }
.grant-table td:nth-child(2), .grant-table td:nth-child(3) { width: 180px; }
.grant-list { display: grid; gap: 6px; }
.grant-list span { display: block; }
.form-actions { display: flex; gap: 10px; align-items: center; }
.facts { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 16px; }
.facts div { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 12px; min-width: 0; }
.facts span { display: block; color: var(--muted); margin-bottom: 6px; }
.facts code { overflow-wrap: anywhere; }
.status { color: var(--muted); }
.status.active, .status.trialing { color: var(--accent); }
.status.revoked, .status.device_blocked { color: var(--danger); }
.status.expired, .status.suspended, .status.unlicensed { color: var(--warn); }
@media (max-width: 760px) {
  nav { padding: 0 12px; gap: 10px; overflow-x: auto; }
  main { width: calc(100vw - 18px); margin-top: 12px; }
  .title-row, .search { display: grid; }
  .grid-form, .package-form, .facts { grid-template-columns: 1fr; }
  table { display: block; overflow-x: auto; }
}
"""


def create_app(settings: Settings | None = None) -> AutoEdgeApp:
    return AutoEdgeApp(settings or Settings.from_env())


def main() -> int:
    settings = Settings.from_env()
    if os.environ.get("AUTOEDGE_SKIP_RUNTIME_VALIDATION") != "1":
        settings.validate_runtime()
    app = create_app(settings)
    with make_server(settings.bind_host, settings.bind_port, app) as server:
        print(f"AutoEdge licensing server listening on http://{settings.bind_host}:{settings.bind_port}", flush=True)
        server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
