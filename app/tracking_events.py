"""Shared email tracking side effects (open, click, unsubscribe).

Used by the public tracking router and the Beacon ingest endpoint.
"""
from __future__ import annotations

# // BEACON SYNC: This file handles tracking logic that Beacon mirrors.
# // Any changes to tracking behavior, event types, metadata collected, or URL structure
# // must also be reflected in the Beacon service (/beacon or the separate Beacon repo).
# // If you are an AI agent, add a TODO at the end of your response listing what needs to be updated in Beacon.

import functools
import ipaddress
import logging
import socket
from typing import TYPE_CHECKING

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import time as time_provider
from app.models import (
    CampaignLead,
    EmailClick,
    EmailLog,
    EmailOpen,
    KnownIP,
    Lead,
    LeadUnsubscribeToken,
    QueueSlot,
    TrackedLink,
)
from app.webhooks import fire_webhook_event

if TYPE_CHECKING:
    pass

log = logging.getLogger("quickly.tracking_events")

_UNSUBSCRIBE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Unsubscribed</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           display: flex; align-items: center; justify-content: center;
           min-height: 100vh; margin: 0; background: #f9fafb; }
    .card { background: #fff; border-radius: 12px; padding: 48px 40px;
            box-shadow: 0 4px 24px rgba(0,0,0,.08); text-align: center; max-width: 420px; }
    .icon { font-size: 48px; margin-bottom: 16px; }
    h1 { margin: 0 0 8px; font-size: 24px; color: #111; }
    p  { color: #555; margin: 0; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">✓</div>
    <h1>You've been unsubscribed</h1>
    <p>You will no longer receive emails from us.<br>
       If this was a mistake please contact the sender directly.</p>
  </div>
</body>
</html>"""

ALREADY_UNSUBSCRIBED_HTML = _UNSUBSCRIBE_HTML.replace(
    "You've been unsubscribed",
    "Already unsubscribed",
).replace(
    "You will no longer receive emails from us.<br>If this was a mistake please contact the sender directly.",
    "You are already unsubscribed and will not receive any more emails from us.",
)

INVALID_UNSUBSCRIBE_HTML = "<p>Invalid or expired unsubscribe link.</p>"


async def is_known_ip(db: AsyncSession, ip: str | None) -> bool:
    if not ip:
        return False

    from app.settings_manager import settings
    if getattr(settings, "test_mode", False):
        return False

    from app.app_settings import get_setting
    filter_enabled = await get_setting(db, "filter_known_ips")
    # Only filter admin IPs if explicitly enabled by user (default is False so testing clicks works)
    if filter_enabled is None or filter_enabled.strip().lower() not in ("true", "1", "yes", "on"):
        return False

    now = time_provider.utcnow()
    result = await db.execute(
        select(KnownIP).where(
            KnownIP.ip_address == ip,
            (KnownIP.permanent == True) | (KnownIP.expires_at > now),  # noqa: E712
        )
    )
    return result.scalar_one_or_none() is not None


async def resolve_email_log_for_open(db: AsyncSession, token: str) -> EmailLog | None:
    result = await db.execute(select(EmailLog).where(EmailLog.open_token == token))
    email_log = result.scalar_one_or_none()
    if email_log is None:
        try:
            log_id = int(token)
            result = await db.execute(select(EmailLog).where(EmailLog.id == log_id))
            email_log = result.scalar_one_or_none()
        except (ValueError, TypeError):
            pass
    return email_log


_APPLE_AND_RELAY_NETS = [
    ipaddress.ip_network("17.0.0.0/8"),       # Apple Inc. ASN 714
    ipaddress.ip_network("104.28.0.0/16"),     # Cloudflare Apple iCloud Private Relay / WARP
    ipaddress.ip_network("104.29.0.0/16"),     # Cloudflare Apple iCloud Private Relay
    ipaddress.ip_network("140.248.0.0/16"),    # Fastly Apple Private Relay
    ipaddress.ip_network("143.244.32.0/19"),   # Apple Cloud Relay
    ipaddress.ip_network("143.244.64.0/19"),   # Apple Cloud Relay
    ipaddress.ip_network("146.75.0.0/16"),     # Fastly Apple Private Relay
    ipaddress.ip_network("151.101.0.0/16"),    # Fastly Apple Private Relay
    ipaddress.ip_network("199.232.0.0/16"),    # Fastly Apple Private Relay
    ipaddress.ip_network("64.252.64.0/18"),    # Apple Cloud Relay
    ipaddress.ip_network("198.54.128.0/18"),   # Apple Cloud Relay
]


@functools.lru_cache(maxsize=1024)
def is_apple_relay_ptr(ip: str) -> bool:
    """Check reverse DNS PTR record for Apple or iCloud relay hostnames."""
    try:
        host = socket.gethostbyaddr(ip)[0].lower()
        return any(k in host for k in ("apple", "icloud", "aaplimg"))
    except Exception:
        return False


def is_apple_or_scanner_ip(ip: str | None) -> bool:
    """Detect Apple Inc. ASN (17.0.0.0/8) and Apple Private Relay / MPP IP ranges."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        for net in _APPLE_AND_RELAY_NETS:
            if addr in net:
                return True
    except ValueError:
        pass
    return False


def is_prefetch_header(headers: dict[str, str] | None) -> bool:
    """Detect explicit prefetch or preview intent declared in request headers."""
    if not headers:
        return False
    for key in ("purpose", "sec-purpose", "x-purpose", "x-moz"):
        val = headers.get(key, "").strip().lower()
        if "prefetch" in val or "preview" in val:
            return True
    return False


def is_bot_user_agent(ua: str | None) -> bool:
    """Detect Apple Mail Privacy Protection (MPP) proxy or automated security bots."""
    if not ua:
        return False
    ua_clean = ua.strip()
    ua_lower = ua_clean.lower()

    # Exact generic signatures (Apple MPP and simple bots)
    if ua_clean in ("Mozilla/5.0", "Mozilla/5.0 ()", "Mozilla/4.0") or ua_lower == "mozilla/5.0":
        return True

    # Apple MPP stripped WebKit proxy signature:
    # Apple strips Version/X.X and Safari/X.X when proxying image fetches
    if "applewebkit" in ua_lower:
        # If it has Mac OS X but NO Version/ and NO Safari/
        if "macintosh" in ua_lower and "version/" not in ua_lower and "safari/" not in ua_lower:
            return True
        # If it has Windows NT but NO Chrome/ and NO Safari/ and NO Firefox/
        if "windows nt" in ua_lower and "chrome/" not in ua_lower and "firefox/" not in ua_lower and "safari/" not in ua_lower:
            return True
        # If it has neither standard browser tokens nor mobile token
        if not any(t in ua_lower for t in ("version/", "safari/", "chrome/", "firefox/", "edg/", "mobile/")):
            return True

    bot_keywords = (
        "bot", "spider", "crawl", "scan", "barracuda", "proofpoint",
        "mimecast", "trend micro", "trendmicro", "sophos", "fireeye",
        "symantec", "postman", "curl", "python-requests", "aiohttp",
        "urllib", "httpx", "wget", "headless", "phantomjs", "virus",
        "mailscanner", "applebot", "apple-mail", "safebrowsing",
        "safelinks", "preview", "validator", "check_http"
    )
    return any(kw in ua_lower for kw in bot_keywords)


def is_immediate_prefetch(sent_at: datetime | None, min_seconds: int = 20) -> bool:
    """Detect instant pre-fetch opens that occur faster than humanly possible."""
    if not sent_at:
        return False
    now = time_provider.utcnow()
    s = sent_at.replace(tzinfo=None) if sent_at.tzinfo else sent_at
    n = now.replace(tzinfo=None) if now.tzinfo else now
    elapsed = (n - s).total_seconds()
    return elapsed < min_seconds


async def record_email_open(
    db: AsyncSession,
    token: str,
    ip: str | None,
    user_agent: str | None = None,
    headers: dict[str, str] | None = None,
) -> bool:
    """Persist open event if applicable. Returns True if an open was recorded."""
    email_log = await resolve_email_log_for_open(db, token)
    if not email_log:
        return False
    if await is_known_ip(db, ip):
        log.debug("open: skipping known IP %s for log_id=%s", ip, email_log.id)
        return False

    from app.settings_manager import settings
    if not getattr(settings, "test_mode", False):
        from app.app_settings import get_setting
        filter_bot_opens = await get_setting(db, "filter_bot_opens")
        # Enabled by default
        if filter_bot_opens is None or filter_bot_opens.strip().lower() in ("true", "1", "yes", "on"):
            # 1. Explicit prefetch headers
            if is_prefetch_header(headers):
                log.info("open: ignoring explicit prefetch header for log_id=%s", email_log.id)
                return False

            # 2. Timing heuristic: 0 to 20 seconds pre-fetch window
            if is_immediate_prefetch(email_log.sent_at, min_seconds=20):
                log.info("open: ignoring immediate pre-fetch (<20s) for log_id=%s", email_log.id)
                return False

            # 3. User-Agent detection (Apple MPP stripped WebKit / bot signatures)
            if is_bot_user_agent(user_agent):
                log.info("open: ignoring bot User-Agent %r for log_id=%s", user_agent, email_log.id)
                return False

            # 4. Apple Inc. (17.0.0.0/8) and Apple Private Relay CIDRs
            if is_apple_or_scanner_ip(ip):
                log.info("open: ignoring Apple MPP / scanner IP %s for log_id=%s", ip, email_log.id)
                return False

            # 5. Reverse DNS check if User-Agent indicates Apple
            if user_agent and "apple" in user_agent.lower() and ip and is_apple_relay_ptr(ip):
                log.info("open: ignoring Apple relay PTR for ip=%s log_id=%s", ip, email_log.id)
                return False

    if not email_log.opened:
        email_log.opened = True
    db.add(
        EmailOpen(
            email_log_id=email_log.id,
            ip_address=ip,
            opened_at=time_provider.utcnow(),
        )
    )
    await db.commit()
    await fire_webhook_event(
        db,
        "email.opened",
        {
            "email_log_id": email_log.id,
            "lead_id": email_log.lead_id,
            "campaign_id": email_log.campaign_id,
            "ip_address": ip,
            "timestamp": time_provider.utcnow().isoformat() + "Z",
        },
    )
    return True


async def resolve_click_redirect_url(db: AsyncSession, token: str) -> str | None:
    result = await db.execute(select(TrackedLink).where(TrackedLink.token == token))
    tracked = result.scalar_one_or_none()
    if not tracked:
        return None
    return tracked.original_url


async def record_email_click(db: AsyncSession, token: str, ip: str | None) -> bool:
    """Record click when TrackedLink exists and rules allow. Returns True if recorded."""
    result = await db.execute(select(TrackedLink).where(TrackedLink.token == token))
    tracked = result.scalar_one_or_none()
    if not tracked:
        return False
    email_log_result = await db.execute(select(EmailLog).where(EmailLog.id == tracked.email_log_id))
    email_log = email_log_result.scalar_one_or_none()
    if not email_log:
        return False
    if await is_known_ip(db, ip):
        log.debug("click: skipping known IP %s for log_id=%s", ip, email_log.id)
        return False
    if not email_log.clicked:
        email_log.clicked = True
    if not email_log.opened:
        email_log.opened = True
    log.info("click: recorded click for email_log_id=%s token=%s ip=%s", email_log.id, token, ip)
    db.add(
        EmailClick(
            email_log_id=tracked.email_log_id,
            ip_address=ip,
            clicked_at=time_provider.utcnow(),
        )
    )
    await db.commit()
    await fire_webhook_event(
        db,
        "email.clicked",
        {
            "email_log_id": tracked.email_log_id,
            "lead_id": email_log.lead_id,
            "campaign_id": email_log.campaign_id,
            "original_url": tracked.original_url,
            "ip_address": ip,
            "timestamp": time_provider.utcnow().isoformat() + "Z",
        },
    )
    return True


async def process_unsubscribe(db: AsyncSession, token: str) -> tuple[str, int]:
    """Run unsubscribe flow; return (html_body, http_status)."""
    result = await db.execute(select(LeadUnsubscribeToken).where(LeadUnsubscribeToken.token == token))
    row = result.scalar_one_or_none()
    if not row:
        return INVALID_UNSUBSCRIBE_HTML, 404

    lead_res = await db.execute(select(Lead).where(Lead.id == row.lead_id))
    lead = lead_res.scalar_one_or_none()

    already_done = False
    cl_res = await db.execute(
        select(CampaignLead).where(
            CampaignLead.lead_id == row.lead_id,
            CampaignLead.campaign_id == row.campaign_id,
        )
    )
    cl = cl_res.scalar_one_or_none()
    if not cl:
        already_done = True
    else:
        if cl.enrollment_status == "unsubscribed":
            already_done = True
        else:
            cl.enrollment_status = "unsubscribed"
            cl.interest_status = None
            log.info(
                "Unsubscribed lead_id=%s via campaign_id=%s token=%s",
                row.lead_id,
                row.campaign_id,
                token,
            )
        await db.execute(delete(QueueSlot).where(QueueSlot.campaign_lead_id == cl.id))

    await db.commit()

    if not already_done and lead and cl:
        await fire_webhook_event(
            db,
            "lead.unsubscribed",
            {
                "lead_id": row.lead_id,
                "lead_email": lead.email if lead else "",
                "campaign_id": row.campaign_id,
                "timestamp": time_provider.utcnow().isoformat() + "Z",
            },
        )
        await fire_webhook_event(
            db,
            "lead.status_changed",
            {
                "lead_id": row.lead_id,
                "lead_email": lead.email if lead else "",
                "campaign_id": row.campaign_id,
                "old_enrollment_status": "active",
                "new_enrollment_status": "unsubscribed",
                "timestamp": time_provider.utcnow().isoformat() + "Z",
            },
        )

    html = ALREADY_UNSUBSCRIBED_HTML if already_done else _UNSUBSCRIBE_HTML
    return html, 200
