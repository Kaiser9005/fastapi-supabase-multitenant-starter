"""
FastAPI + Supabase multi-tenant starter.

The teaching point: the API forwards the *caller's* JWT to Supabase on every
request, so Postgres RLS (migrations/0001) enforces tenant isolation — the app
code contains ZERO `where tenant_id = ...` filters. Isolation is a database
guarantee, not an application convention you can forget.

The service-role key (which BYPASSES RLS) is never used on a request path; it's
only for trusted server-side jobs. Mixing it into request handling is the #1 way
teams accidentally leak across tenants.

Run:
    uvicorn app.main:app --reload
Then call with a Supabase user JWT:
    curl -H "Authorization: Bearer <user-jwt>" localhost:8000/widgets
"""
from __future__ import annotations

import os

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from supabase import Client, create_client

load_dotenv()

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_ANON_KEY = os.environ["SUPABASE_ANON_KEY"]

app = FastAPI(title="multitenant-starter")


# ─── Per-request, RLS-enforced Supabase client ──────────────────────────────
def tenant_client(authorization: str = Header(...)) -> Client:
    """
    Build a Supabase client authenticated AS THE CALLER, so every query runs
    under the caller's JWT and Postgres RLS scopes it to their tenant.

    We use the ANON key (RLS-enforced) and attach the caller's bearer token —
    NOT the service-role key (which would bypass RLS and see every tenant).
    """
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Missing Bearer token")
    jwt = authorization.split(" ", 1)[1]

    client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    # Forward the caller's JWT → PostgREST runs the query as that user → RLS applies.
    client.postgrest.auth(jwt)
    return client


# ─── Models ──────────────────────────────────────────────────────────────────
class WidgetIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    quantity: int = Field(default=0, ge=0)


class Widget(WidgetIn):
    id: str
    tenant_id: str
    created_at: str


# ─── Routes — note: NO tenant_id filter anywhere; RLS does it ───────────────
@app.get("/widgets", response_model=list[Widget])
def list_widgets(db: Client = Depends(tenant_client)):
    # RLS limits this to the caller's tenant automatically.
    res = db.table("widgets").select("*").order("created_at", desc=True).execute()
    return res.data


@app.post("/widgets", response_model=Widget, status_code=201)
def create_widget(body: WidgetIn, db: Client = Depends(tenant_client)):
    # tenant_id is auto-stamped by the column DEFAULT public.tenant_id() — we never
    # send it from the app, so we can never send the WRONG one.
    res = db.table("widgets").insert(body.model_dump()).execute()
    if not res.data:
        raise HTTPException(400, "Insert failed (RLS WITH CHECK or validation)")
    return res.data[0]


@app.get("/widgets/{widget_id}", response_model=Widget)
def get_widget(widget_id: str, db: Client = Depends(tenant_client)):
    res = db.table("widgets").select("*").eq("id", widget_id).execute()
    if not res.data:
        # Either it doesn't exist OR it belongs to another tenant — RLS makes those
        # indistinguishable, which is exactly the privacy property you want.
        raise HTTPException(404, "Not found")
    return res.data[0]


@app.get("/health")
def health():
    return {"status": "ok"}
