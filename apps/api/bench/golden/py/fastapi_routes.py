from fastapi import APIRouter, Query, Request
from sqlmodel import Session, text
import subprocess, requests

router = APIRouter()


@router.get("/items")
def search_items(session: Session, q: str = Query(...)):
    return session.exec(text(f"SELECT * FROM item WHERE title = '{q}'")).all()  # VULN: SQLI


@router.get("/ping/{host}")
def ping(host: str):
    return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True).stdout  # VULN: CMDI


@router.post("/fetch")
async def fetch(request: Request):
    body = await request.json()
    return requests.get(body["url"]).text  # VULN: SSRF


@router.get("/items/{item_id}")
def read_item(session: Session, item_id: int):
    return session.exec(text(f"SELECT * FROM item WHERE id = {item_id}")).first()  # SAFE: SQLI


def build_report(title: str):
    return text(f"SELECT * FROM report WHERE title = '{title}'")
