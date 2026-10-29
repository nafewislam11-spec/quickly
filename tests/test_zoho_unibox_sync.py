import json
import urllib.error
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import select

from app.models import Campaign, CampaignLead, EmailLog, GmailMessage, GmailThread, Inbox, Lead, LeadReply, QueueSlot, ZohoAccount
from app.unibox import _sync_inbox_zoho
from tests.conftest import make_campaign, make_campaign_lead, make_inbox, make_lead


@pytest.mark.asyncio
async def test_zoho_sync_fallback_to_search_and_marks_interested(session):
    """Scenario: User token lacks folders scope, folders API returns 403, but /messages/search succeeds.
    Verify:
    1. Incoming message from lead is retrieved via search fallback
    2. LeadReply is created
    3. CampaignLead.enrollment_status becomes 'replied'
    4. CampaignLead.interest_status becomes 'interested'
    5. Future QueueSlot is deleted
    6. GmailMessage and GmailThread are created in Unibox
    """
    inbox = Inbox(email="user@zoho.com", provider="zoho")
    session.add(inbox)
    await session.flush()

    zoho_acc = ZohoAccount(
        inbox_id=inbox.id,
        zoho_email="user@zoho.com",
        zoho_account_id="acc12345",
        access_token="fake-zoho-token",
        refresh_token="fake-refresh-token",
        region="com",
    )
    session.add(zoho_acc)

    lead = Lead(email="prospect@client.com", name="Prospect Person")
    session.add(lead)
    await session.flush()

    camp = Campaign(name="Outreach 1", status="running", user_id=1)
    session.add(camp)
    await session.flush()

    cl = CampaignLead(
        campaign_id=camp.id,
        lead_id=lead.id,
        enrollment_status="active",
        interest_status=None,
    )
    session.add(cl)
    await session.flush()

    qs = QueueSlot(
        campaign_lead_id=cl.id,
        scheduled_for=datetime.utcnow(),
        status="pending",
    )
    session.add(qs)

    email_log = EmailLog(
        lead_id=lead.id,
        campaign_id=camp.id,
        inbox_id=inbox.id,
        subject="Quick question",
        thread_id="zoho-thread-orig",
        message_id="<orig-123@zoho.com>",
    )
    session.add(email_log)
    await session.flush()

    # Mock Zoho HTTP responses
    def mock_urlopen(req, timeout=None):
        url = req.full_url
        mock_resp = MagicMock()
        # 1. Folders endpoint returns 403 (missing ZohoMail.folders.READ scope)
        if "/folders" in url and not "/messages/" in url:
            raise urllib.error.HTTPError(url, 403, "Access Denied: Missing folders scope", {}, None)

        # 2. Search endpoint returns the lead's reply message
        if "/messages/search" in url:
            data = {
                "status": {"code": 200, "description": "success"},
                "data": [
                    {
                        "messageId": "msg-zoho-999",
                        "folderId": "folder-inbox-101",
                        "sender": "prospect@client.com",
                        "senderName": "Prospect Person",
                        "fromAddress": "Prospect Person <prospect@client.com>",
                        "toAddress": "user@zoho.com",
                        "subject": "Re: Quick question",
                        "summary": "Yes, I am interested! Let's schedule a call.",
                        "receivedTime": "1698650000000",
                        "inReplyTo": "<orig-123@zoho.com>",
                    }
                ],
            }
            mock_resp.read.return_value = json.dumps(data).encode("utf-8")
            return mock_resp

        # 3. Message content endpoint
        if "/content" in url:
            data = {
                "status": {"code": 200, "description": "success"},
                "data": {
                    "content": "<p>Yes, I am interested! Let's schedule a call.</p>"
                },
            }
            mock_resp.read.return_value = json.dumps(data).encode("utf-8")
            return mock_resp

        # 4. View endpoint if called
        if "/messages/view" in url:
            data = {"status": {"code": 200, "description": "success"}, "data": []}
            mock_resp.read.return_value = json.dumps(data).encode("utf-8")
            return mock_resp

        mock_resp.read.return_value = json.dumps({"data": []}).encode("utf-8")
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        touched = await _sync_inbox_zoho(session, inbox, reason="test")

    assert len(touched) > 0

    # Verify LeadReply was created
    reply_res = await session.execute(
        select(LeadReply).where(LeadReply.lead_id == lead.id, LeadReply.campaign_id == camp.id)
    )
    reply = reply_res.scalar_one_or_none()
    assert reply is not None

    # Verify CampaignLead updated to replied and interested
    cl_refreshed = (await session.execute(
        select(CampaignLead).where(CampaignLead.id == cl.id)
    )).scalar_one()
    assert cl_refreshed.enrollment_status == "replied"
    assert cl_refreshed.interest_status == "interested"

    # Verify QueueSlot was deleted
    qs_res = await session.execute(
        select(QueueSlot).where(QueueSlot.campaign_lead_id == cl.id)
    )
    assert qs_res.scalar_one_or_none() is None

    # Verify message in Unibox
    msg_res = await session.execute(
        select(GmailMessage).where(GmailMessage.inbox_id == inbox.id, GmailMessage.message_id == "zoho:msg-zoho-999")
    )
    stored_msg = msg_res.scalar_one_or_none()
    assert stored_msg is not None
    assert "interested" in (stored_msg.body_plain or "")
