"""Zoho Mail OAuth 2.0 routes for connecting accounts and sending emails."""
import hmac
import json
import logging
import secrets
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.settings_manager import settings
from app.database import get_db
from app.models import Inbox, ZohoAccount, OAuthState

log = logging.getLogger("quickly.zoho_oauth")

router = APIRouter(tags=["zoho-oauth"])
# Public router for OAuth callback redirect
callback_router = APIRouter(tags=["zoho-oauth"])

ZOHO_SCOPES = [
    "ZohoMail.messages.ALL",
    "ZohoMail.accounts.READ",
    "offline_access",
]


class ZohoSettingsUpdate(BaseModel):
    client_id: str = ""
    client_secret: str = ""
    region: str = "com"


def _get_accounts_url(region: str) -> str:
    """Return Zoho accounts base URL for the given region."""
    reg = (region or "com").strip().lower()
    return f"https://accounts.zoho.{reg}"


def _get_mail_api_url(region: str, api_domain: str = "") -> str:
    """Return Zoho Mail API base URL for the given region or returned api_domain."""
    if api_domain:
        return api_domain.rstrip("/")
    reg = (region or "com").strip().lower()
    return f"https://mail.zoho.{reg}"


@router.get("/api/zoho/status")
async def zoho_oauth_status(db: AsyncSession = Depends(get_db)):
    """Check if Zoho Mail OAuth credentials are configured."""
    from app.app_settings import get_zoho_oauth_credentials
    client_id, client_secret, region = await get_zoho_oauth_credentials(db)
    configured = bool(client_id and client_secret)
    return {
        "configured": configured,
        "client_id": client_id,
        "has_secret": bool(client_secret),
        "region": region or "com",
        "redirect_uri": settings.zoho_redirect_uri,
    }


@router.post("/api/zoho/settings")
async def update_zoho_settings(
    payload: ZohoSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    """Update Zoho Mail OAuth settings from UI."""
    from app.app_settings import save_zoho_oauth_credentials
    reg = payload.region.strip().lower() or "com"
    await save_zoho_oauth_credentials(
        db,
        client_id=payload.client_id.strip(),
        client_secret=payload.client_secret.strip(),
        region=reg,
    )
    await db.commit()
    return {
        "ok": True,
        "configured": bool(settings.zoho_client_id and settings.zoho_client_secret),
        "region": settings.zoho_region,
        "redirect_uri": settings.zoho_redirect_uri,
    }


@router.get("/api/zoho/accounts")
async def list_zoho_accounts(
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    """List all connected Zoho Mail accounts."""
    result = await db.execute(
        select(ZohoAccount, Inbox)
        .join(Inbox, ZohoAccount.inbox_id == Inbox.id)
        .order_by(ZohoAccount.created_at.desc())
    )
    rows = result.all()
    return [
        {
            "id": za.id,
            "inbox_id": za.inbox_id,
            "zoho_email": za.zoho_email,
            "zoho_account_id": za.zoho_account_id,
            "inbox_email": inbox.email,
            "inbox_display_name": inbox.display_name,
            "max_emails_per_day": inbox.max_emails_per_day,
            "region": za.region,
            "token_expiry": za.token_expiry.isoformat() if za.token_expiry else None,
            "connected_at": za.created_at.isoformat() if za.created_at else None,
        }
        for za, inbox in rows
    ]


@router.get("/oauth/zoho/authorize")
async def zoho_authorize(
    display_name: str = "",
    max_per_day: int = 50,
    ramp_up_enabled: bool = False,
    ramp_up_start: int = 1,
    ramp_up_step_size: int = 1,
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    """Redirect user to Zoho consent screen."""
    from app.app_settings import get_zoho_oauth_credentials
    client_id, client_secret, region = await get_zoho_oauth_credentials(db)
    if not client_id or not client_secret:
        raise HTTPException(
            400,
            "Zoho Mail OAuth not configured. Set ZOHO_CLIENT_ID and ZOHO_CLIENT_SECRET environment variables or configure them in Settings.",
        )

    # CSRF nonce
    from app.time import utcnow
    csrf_token = secrets.token_urlsafe(32)
    csrf_state = OAuthState(
        state_token=csrf_token,
        purpose="inbox_zoho",
        metadata_json=json.dumps({
            "display_name": display_name,
            "max_per_day": max_per_day,
            "ramp_up_enabled": ramp_up_enabled,
            "ramp_up_start": ramp_up_start,
            "ramp_up_step_size": ramp_up_step_size,
        }),
        expires_at=utcnow() + timedelta(minutes=10),
    )
    db.add(csrf_state)
    await db.flush()

    state_data = json.dumps({
        "display_name": display_name,
        "max_per_day": max_per_day,
        "ramp_up_enabled": ramp_up_enabled,
        "ramp_up_start": ramp_up_start,
        "ramp_up_step_size": ramp_up_step_size,
        "_csrf": csrf_token,
    })

    accounts_url = _get_accounts_url(region)
    params = {
        "client_id": client_id,
        "redirect_uri": settings.zoho_redirect_uri,
        "response_type": "code",
        "scope": ",".join(ZOHO_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state_data,
    }
    url = f"{accounts_url}/oauth/v2/auth?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url)


@callback_router.get("/oauth/zoho/callback")
async def zoho_callback(
    request: Request,
    background_tasks: BackgroundTasks,
    code: str = "",
    error: str = "",
    error_description: str = "",
    state: str = "{}",
    db: AsyncSession = Depends(get_db),
):
    """Handle Zoho OAuth callback — exchange code for tokens, create inbox + zoho_account."""
    if error:
        raise HTTPException(400, f"Zoho OAuth error: {error} — {error_description}")
    if not code:
        raise HTTPException(400, "No authorization code received from Zoho")

    try:
        state_data = json.loads(state)
    except (json.JSONDecodeError, TypeError):
        state_data = {}

    display_name = state_data.get("display_name", "")
    max_per_day = state_data.get("max_per_day", 50)
    wait_minutes_between = state_data.get("wait_minutes_between", 5)
    max_jitter_seconds = state_data.get("max_jitter_seconds", 180)
    tracking_domain = state_data.get("tracking_domain", "") or None
    ramp_up_enabled = bool(state_data.get("ramp_up_enabled", False))
    ramp_up_start = int(state_data.get("ramp_up_start", 1))
    ramp_up_step_size = int(state_data.get("ramp_up_step_size", 1))
    source = state_data.get("source", "")

    # Validate CSRF nonce (single-use)
    csrf_token = state_data.get("_csrf", "")
    if not csrf_token:
        raise HTTPException(403, "Missing CSRF token in OAuth state")

    csrf_result = await db.execute(
        select(OAuthState).where(OAuthState.state_token == csrf_token)
    )
    csrf_record = csrf_result.scalar_one_or_none()
    if csrf_record is None:
        raise HTTPException(403, "Invalid or expired OAuth state")

    from app.time import utcnow as _utcnow_fn
    if not hmac.compare_digest(csrf_record.purpose, "inbox_zoho"):
        await db.delete(csrf_record)
        await db.flush()
        raise HTTPException(403, "Invalid OAuth state purpose")
    if csrf_record.expires_at < _utcnow_fn():
        await db.delete(csrf_record)
        await db.flush()
        raise HTTPException(403, "OAuth state expired")

    await db.delete(csrf_record)
    await db.flush()

    from app.app_settings import get_zoho_oauth_credentials
    client_id, client_secret, region = await get_zoho_oauth_credentials(db)

    # Exchange code for tokens
    token_data = _exchange_code(code, client_id, client_secret, region)
    if not token_data or "access_token" not in token_data:
        err_msg = token_data.get("error", "Unknown token exchange failure") if token_data else "Failed to contact Zoho"
        raise HTTPException(502, f"Failed to exchange authorization code for tokens: {err_msg}")

    access_token = token_data.get("access_token", "")
    refresh_token = token_data.get("refresh_token", "")
    expires_in = token_data.get("expires_in", 3600)
    api_domain = token_data.get("api_domain", "")
    token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)

    # Fetch user account details from Zoho Mail API
    user_email, zoho_account_id = _get_user_account_info(access_token, region, api_domain)
    if not user_email:
        raise HTTPException(502, "Failed to retrieve primary email address from Zoho Mail API")

    # Check if inbox already exists for this email
    result = await db.execute(select(Inbox).where(Inbox.email == user_email))
    inbox = result.scalar_one_or_none()

    if inbox:
        inbox.provider = "zoho"
        if display_name:
            inbox.display_name = display_name

        result2 = await db.execute(
            select(ZohoAccount).where(ZohoAccount.inbox_id == inbox.id)
        )
        za = result2.scalar_one_or_none()
        if za:
            za.access_token = access_token
            if refresh_token:
                za.refresh_token = refresh_token
            za.token_expiry = token_expiry
            za.zoho_email = user_email
            za.zoho_account_id = zoho_account_id or za.zoho_account_id
            za.region = region
            za.api_domain = api_domain
            za.updated_at = datetime.utcnow()
        else:
            if not refresh_token:
                raise HTTPException(400, "No refresh token received from Zoho. Please revoke existing Quickly access in Zoho Accounts and reconnect.")
            za = ZohoAccount(
                inbox_id=inbox.id,
                zoho_email=user_email,
                zoho_account_id=zoho_account_id,
                access_token=access_token,
                refresh_token=refresh_token,
                token_expiry=token_expiry,
                region=region,
                api_domain=api_domain,
            )
            db.add(za)
    else:
        if not refresh_token:
            raise HTTPException(400, "No refresh token received from Zoho. Please reconnect with consent prompt.")
        inbox = Inbox(
            email=user_email,
            display_name=display_name or user_email.split("@")[0],
            max_emails_per_day=max_per_day,
            wait_minutes_between=wait_minutes_between,
            max_jitter_seconds=max_jitter_seconds,
            provider="zoho",
            tracking_domain=tracking_domain,
            ramp_up_enabled=ramp_up_enabled,
            ramp_up_start=ramp_up_start,
            ramp_up_step_size=ramp_up_step_size,
            ramp_up_started_at=datetime.utcnow() if ramp_up_enabled else None,
        )
        db.add(inbox)
        await db.flush()

        za = ZohoAccount(
            inbox_id=inbox.id,
            zoho_email=user_email,
            zoho_account_id=zoho_account_id,
            access_token=access_token,
            refresh_token=refresh_token,
            token_expiry=token_expiry,
            region=region,
            api_domain=api_domain,
        )
        db.add(za)

    await db.commit()
    log.info("Zoho Mail OAuth connected: %s (inbox_id=%s, account_id=%s)", user_email, inbox.id, zoho_account_id)

    base = settings.base_url.rstrip("/")
    if source == "connect_url":
        from app.auth import SECRET_KEY
        sig = hmac.new(SECRET_KEY.encode(), user_email.encode(), "sha256").hexdigest()[:12]
        target = f"{base}/oauth/connected?email=" + urllib.parse.quote(user_email) + "&sig=" + sig
    else:
        target = f"{base}/inboxes?connected=" + urllib.parse.quote(user_email)
    return RedirectResponse(target, status_code=303)


@router.delete("/api/zoho/accounts/{account_id}")
async def disconnect_zoho(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    """Disconnect a Zoho Mail account (removes tokens)."""
    result = await db.execute(
        select(ZohoAccount).where(ZohoAccount.id == account_id)
    )
    za = result.scalar_one_or_none()
    if not za:
        raise HTTPException(404, "Zoho account not found")

    result2 = await db.execute(select(Inbox).where(Inbox.id == za.inbox_id))
    inbox = result2.scalar_one_or_none()

    email = za.zoho_email
    await db.delete(za)
    if inbox and inbox.provider == "zoho":
        inbox.provider = "smtp"
    await db.flush()
    log.info("Zoho Mail disconnected: %s", email)
    return {"ok": True, "email": email}


# ---- Helper functions ----

def _exchange_code(code: str, client_id: str, client_secret: str, region: str) -> dict | None:
    """Exchange authorization code for access/refresh tokens via Zoho token endpoint."""
    accounts_url = _get_accounts_url(region)
    token_url = f"{accounts_url}/oauth/v2/token"

    data = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": settings.zoho_redirect_uri,
        "grant_type": "authorization_code",
    }).encode()

    req = urllib.request.Request(
        token_url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()
        except Exception:
            pass
        log.error("Zoho token exchange HTTP %s: %s", e.code, body)
        return None
    except Exception as e:
        log.error("Zoho token exchange error: %s", e)
        return None


def _get_user_account_info(access_token: str, region: str, api_domain: str = "") -> tuple[str | None, str | None]:
    """Fetch user primary email and accountId from Zoho Mail /api/accounts endpoint."""
    mail_url = _get_mail_api_url(region, api_domain)
    req = urllib.request.Request(
        f"{mail_url}/api/accounts",
        headers={"Authorization": f"Zoho-oauthtoken {access_token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            payload = json.loads(resp.read().decode())
            data = payload.get("data", [])
            if isinstance(data, list) and len(data) > 0:
                first = data[0]
                email = first.get("primaryEmailAddress") or first.get("incomingUserName")
                acc_id = str(first.get("accountId") or "")
                return email, acc_id
            return None, None
    except Exception as e:
        log.error("Zoho Mail /api/accounts error: %s", e)
        return None, None


def refresh_access_token(
    zoho_account: ZohoAccount,
    client_id: str = "",
    client_secret: str = "",
    region: str = "",
) -> str | None:
    """Refresh the access token using the refresh token. Updates the model in-place."""
    _cid = client_id or settings.zoho_client_id
    _csec = client_secret or settings.zoho_client_secret
    _reg = region or zoho_account.region or settings.zoho_region or "com"

    accounts_url = _get_accounts_url(_reg)
    token_url = f"{accounts_url}/oauth/v2/token"

    data = urllib.parse.urlencode({
        "client_id": _cid,
        "client_secret": _csec,
        "refresh_token": zoho_account.refresh_token,
        "grant_type": "refresh_token",
    }).encode()

    req = urllib.request.Request(
        token_url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            token_data = json.loads(resp.read().decode())
            if "access_token" in token_data:
                zoho_account.access_token = token_data["access_token"]
                zoho_account.token_expiry = datetime.utcnow() + timedelta(
                    seconds=token_data.get("expires_in", 3600)
                )
                zoho_account.updated_at = datetime.utcnow()
                log.info("Refreshed Zoho token for %s", zoho_account.zoho_email)
                return zoho_account.access_token
            else:
                log.error("Zoho refresh token response missing access_token: %s", token_data)
                return None
    except Exception as e:
        log.error("Failed to refresh Zoho token for %s: %s", zoho_account.zoho_email, e)
        return None
