import os
import json
import hmac
import hashlib
from fastapi import FastAPI, Request, HTTPException
import asyncpg

app = FastAPI()

SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL")
MAILGUN_SIGNING_KEY = os.getenv("MAILGUN_SIGNING_KEY")


def verify_mailgun_signature(timestamp: str, token: str, signature: str) -> bool:
    """Verify Mailgun webhook signature."""
    expected = hmac.new(
        key=MAILGUN_SIGNING_KEY.encode(),
        msg=f"{timestamp}{token}".encode(),
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


@app.post("/mailgun/webhook")
async def mailgun_webhook(request: Request):
    print("DEBUG SUPABASE_DB_URL =", os.getenv("SUPABASE_DB_URL"))
    body = await request.json()

    # Extract signature fields
    try:
        timestamp = body["signature"]["timestamp"]
        token = body["signature"]["token"]
        signature = body["signature"]["signature"]
    except KeyError:
        raise HTTPException(status_code=400, detail="Invalid signature payload")

    # Verify signature
    if not verify_mailgun_signature(timestamp, token, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Extract event data
    event_data = body.get("event-data", {})
    event_type = event_data.get("event")
    recipient = event_data.get("recipient")
    message_id = (
        event_data.get("message", {})
        .get("headers", {})
        .get("message-id")
    )

    # Insert into Supabase
    conn = await asyncpg.connect(SUPABASE_DB_URL)
    await conn.execute(
        """
        INSERT INTO mailgun_events (event_type, recipient, message_id, payload)
        VALUES ($1, $2, $3, $4)
        """,
        event_type,
        recipient,
        message_id,
        json.dumps(body)
    )
    await conn.close()

    return {"status": "ok"}
