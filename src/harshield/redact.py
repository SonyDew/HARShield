"""Conservative redaction of common credentials in HAR 1.2 documents."""

from __future__ import annotations

import copy
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MARKER = "[REDACTED]"
_SENSITIVE = (
    "authorization", "authentication", "password", "passwd", "secret",
    "token", "apikey", "accesskey", "privatekey", "sessionid", "sessionkey",
    "credential", "cookie", "csrf", "xsrf", "signature", "jwt",
)
_AUTH_VALUE = re.compile(r"^\s*(?:bearer|basic|digest)\s+", re.IGNORECASE)


class InvalidHAR(ValueError):
    """The document cannot be processed safely as a HAR file."""


def sensitive_name(name: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", name.lower())
    return any(part in compact for part in _SENSITIVE) or compact in {
        "key", "code", "sig", "otp", "pin", "state", "auth",
    }


def _replace(item: dict, key: str, stats: list[int]) -> None:
    if key in item and item[key] != MARKER and item[key] not in (None, ""):
        item[key] = MARKER
        stats[0] += 1


def _remove_metadata(value: object, stats: list[int]) -> None:
    if isinstance(value, dict):
        for key in list(value):
            if key == "comment" or key.startswith("_"):
                del value[key]
                stats[0] += 1
            else:
                _remove_metadata(value[key], stats)
    elif isinstance(value, list):
        for item in value:
            _remove_metadata(item, stats)


def _url(value: str, stats: list[int]) -> str:
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise InvalidHAR("Invalid URL in HAR") from exc
    changed = False
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, host = netloc.rsplit("@", 1)
        if userinfo != "%5BREDACTED%5D":
            netloc = "%5BREDACTED%5D@" + host
            stats[0] += 1
            changed = True
    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        new_pairs = []
        for name, val in pairs:
            if sensitive_name(name) and val and val != MARKER:
                val = MARKER
                stats[0] += 1
                changed = True
            new_pairs.append((name, val))
        if changed:
            query = urlencode(new_pairs)
    if parts.fragment:
        stats[0] += 1
        changed = True
    if not changed:
        return value
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def _items(parent: dict, field: str, stats: list[int], *, kind: str) -> None:
    if field not in parent:
        return
    items = parent[field]
    if not isinstance(items, list):
        raise InvalidHAR(f"Invalid {field} list")
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise InvalidHAR(f"Invalid {field} item")
        name = item["name"]
        if kind == "cookie" or kind == "param" or sensitive_name(name):
            _replace(item, "value", stats)
        elif kind == "header" and isinstance(item.get("value"), str):
            if _AUTH_VALUE.match(item["value"]):
                _replace(item, "value", stats)
            elif name.lower() in {"location", "referer", "referrer"}:
                item["value"] = _url(item["value"], stats)
        if kind == "param":
            _replace(item, "fileName", stats)


def redact_har(document: object) -> tuple[dict, int]:
    """Return a redacted copy and the number of modified or removed fields."""
    if not isinstance(document, dict) or not isinstance(document.get("log"), dict):
        raise InvalidHAR("Expected a HAR log object")
    log = document["log"]
    if not isinstance(log.get("entries"), list):
        raise InvalidHAR("Expected a HAR entries list")
    result = copy.deepcopy(document)
    stats = [0]
    _remove_metadata(result, stats)
    for entry in result["log"]["entries"]:
        if not isinstance(entry, dict):
            raise InvalidHAR("Invalid HAR entry")
        for field in ("request", "response"):
            if not isinstance(entry.get(field), dict):
                raise InvalidHAR(f"Invalid HAR {field}")
        request = entry["request"]
        response = entry["response"]
        if not isinstance(request.get("url"), str):
            raise InvalidHAR("Invalid request URL")
        request["url"] = _url(request["url"], stats)
        if "redirectURL" in response:
            if not isinstance(response["redirectURL"], str):
                raise InvalidHAR("Invalid redirect URL")
            response["redirectURL"] = _url(response["redirectURL"], stats)
        for side in (request, response):
            _items(side, "headers", stats, kind="header")
            _items(side, "cookies", stats, kind="cookie")
        _items(request, "queryString", stats, kind="query")
        if "postData" in request:
            post = request["postData"]
            if not isinstance(post, dict):
                raise InvalidHAR("Invalid postData")
            _items(post, "params", stats, kind="param")
            _replace(post, "text", stats)
        if "content" in response:
            content = response["content"]
            if not isinstance(content, dict):
                raise InvalidHAR("Invalid response content")
            _replace(content, "text", stats)
            if content.get("text") == MARKER and "encoding" in content:
                del content["encoding"]
                stats[0] += 1
    return result, stats[0]
