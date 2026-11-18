"""
Wazuh MCP-server (minimal) – Emne 3, Gokstad Akademiet

Eksponerer Wazuh som verktøy en AI-agent kan kalle.
Kun lesetilgang. Ingen endringer i Wazuh.

Miljøvariabler (sett i .env eller i MCP-config):
  WAZUH_API_URL      f.eks. https://10.0.0.5:55000   (manager API)
  WAZUH_API_USER     f.eks. wazuh
  WAZUH_API_PASS
  WAZUH_INDEXER_URL  f.eks. https://10.0.0.5:9200    (indexer / OpenSearch)
  WAZUH_INDEXER_USER f.eks. admin
  WAZUH_INDEXER_PASS
  WAZUH_VERIFY_SSL   "false" i lab (selvsignerte sertifikater)

Kjør:  python wazuh_mcp.py          (stdio-transport, for Claude Desktop / Claude Code)
Test:  python wazuh_mcp.py --selftest
"""

import os
import sys
import json
import time
from datetime import datetime, timedelta, timezone

import httpx

try:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP

# ---------- konfig ----------
API_URL = os.getenv("WAZUH_API_URL", "https://127.0.0.1:55000").rstrip("/")
API_USER = os.getenv("WAZUH_API_USER", "wazuh")
API_PASS = os.getenv("WAZUH_API_PASS", "wazuh")
IDX_URL = os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200").rstrip("/")
IDX_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
IDX_PASS = os.getenv("WAZUH_INDEXER_PASS", "admin")
VERIFY = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"

mcp = FastMCP("wazuh")

_token_cache = {"token": None, "exp": 0.0}


def _api_token() -> str:
    """Hent JWT fra manager-API (gyldig ~15 min). Cacher."""
    if _token_cache["token"] and time.time() < _token_cache["exp"]:
        return _token_cache["token"]
    r = httpx.post(
        f"{API_URL}/security/user/authenticate",
        auth=(API_USER, API_PASS),
        verify=VERIFY,
        timeout=15,
    )
    r.raise_for_status()
    tok = r.json()["data"]["token"]
    _token_cache.update(token=tok, exp=time.time() + 600)
    return tok


def _api_get(path: str, params: dict | None = None) -> dict:
    r = httpx.get(
        f"{API_URL}{path}",
        headers={"Authorization": f"Bearer {_api_token()}"},
        params=params,
        verify=VERIFY,
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def _idx_search(body: dict) -> dict:
    r = httpx.post(
        f"{IDX_URL}/wazuh-alerts-*/_search",
        auth=(IDX_USER, IDX_PASS),
        json=body,
        verify=VERIFY,
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def _since(minutes: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


# ---------- tools ----------
@mcp.tool()
def wazuh_status() -> str:
    """Sjekk at MCP-serveren når både manager-API og indexer. Kjør denne først."""
    out = {}
    try:
        info = _api_get("/")
        out["manager"] = {"ok": True, "version": info.get("data", {}).get("api_version")}
    except Exception as e:  # noqa: BLE001
        out["manager"] = {"ok": False, "error": str(e)}
    try:
        r = httpx.get(IDX_URL, auth=(IDX_USER, IDX_PASS), verify=VERIFY, timeout=15)
        r.raise_for_status()
        out["indexer"] = {"ok": True, "version": r.json().get("version", {}).get("number")}
    except Exception as e:  # noqa: BLE001
        out["indexer"] = {"ok": False, "error": str(e)}
    return json.dumps(out, indent=2)


@mcp.tool()
def list_agents() -> str:
    """List alle Wazuh-agenter med status (active/disconnected), IP og OS."""
    data = _api_get("/agents", {"select": "id,name,ip,status,os.name,lastKeepAlive", "limit": 100})
    items = data.get("data", {}).get("affected_items", [])
    return json.dumps(items, indent=2)


@mcp.tool()
def search_alerts(
    minutes: int = 60,
    min_level: int = 5,
    agent_name: str = "",
    text: str = "",
    limit: int = 50,
) -> str:
    """
    Søk i Wazuh-alarmer (wazuh-alerts-*).
    minutes: hvor langt tilbake i tid. min_level: laveste rule.level (0-15).
    agent_name: filtrer på agent. text: fritekst (f.eks. 'sshd', 'sudo', 'suricata').
    Returnerer tidspunkt, agent, rule.id, level, beskrivelse, MITRE-teknikker og kort logglinje.
    """
    must = [
        {"range": {"@timestamp": {"gte": _since(minutes)}}},
        {"range": {"rule.level": {"gte": min_level}}},
    ]
    if agent_name:
        must.append({"term": {"agent.name": agent_name}})
    if text:
        must.append({"query_string": {"query": text}})

    body = {
        "size": min(limit, 200),
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
        "_source": [
            "@timestamp", "agent.name", "rule.id", "rule.level", "rule.description",
            "rule.mitre.id", "rule.mitre.technique", "data.srcip", "data.srcuser",
            "data.dstuser", "full_log",
        ],
    }
    res = _idx_search(body)
    hits = []
    for h in res.get("hits", {}).get("hits", []):
        s = h["_source"]
        hits.append({
            "time": s.get("@timestamp"),
            "agent": s.get("agent", {}).get("name"),
            "rule_id": s.get("rule", {}).get("id"),
            "level": s.get("rule", {}).get("level"),
            "description": s.get("rule", {}).get("description"),
            "mitre": s.get("rule", {}).get("mitre", {}).get("id"),
            "srcip": s.get("data", {}).get("srcip"),
            "user": s.get("data", {}).get("srcuser") or s.get("data", {}).get("dstuser"),
            "log": (s.get("full_log") or "")[:200],
        })
    total = res.get("hits", {}).get("total", {}).get("value", len(hits))
    return json.dumps({"total": total, "returned": len(hits), "alerts": hits}, indent=2)


@mcp.tool()
def top_rules(minutes: int = 60, size: int = 15) -> str:
    """Hvilke regler har fyrt mest siste N minutter? Bra for å finne støy / falske positiver."""
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": _since(minutes)}}},
        "aggs": {
            "rules": {
                "terms": {"field": "rule.id", "size": size},
                "aggs": {
                    "desc": {"terms": {"field": "rule.description", "size": 1}},
                    "level": {"max": {"field": "rule.level"}},
                },
            }
        },
    }
    res = _idx_search(body)
    out = []
    for b in res.get("aggregations", {}).get("rules", {}).get("buckets", []):
        d = b["desc"]["buckets"][0]["key"] if b["desc"]["buckets"] else ""
        out.append({"rule_id": b["key"], "count": b["doc_count"], "level": b["level"]["value"], "description": d})
    return json.dumps(out, indent=2)


@mcp.tool()
def get_rule(rule_id: str) -> str:
    """Hent detaljer om én Wazuh-regel (fil, nivå, grupper, MITRE) fra manager-API."""
    data = _api_get("/rules", {"rule_ids": rule_id})
    return json.dumps(data.get("data", {}).get("affected_items", []), indent=2)


@mcp.tool()
def top_source_ips(minutes: int = 60, size: int = 10) -> str:
    """Hvilke kilde-IP-er står bak flest alarmer? Nyttig ved brute force / scanning."""
    body = {
        "size": 0,
        "query": {
            "bool": {"must": [
                {"range": {"@timestamp": {"gte": _since(minutes)}}},
                {"exists": {"field": "data.srcip"}},
            ]}
        },
        "aggs": {"ips": {"terms": {"field": "data.srcip", "size": size}}},
    }
    res = _idx_search(body)
    return json.dumps(
        [{"srcip": b["key"], "count": b["doc_count"]} for b in res["aggregations"]["ips"]["buckets"]],
        indent=2,
    )


# ---------- main ----------
if __name__ == "__main__":
    if "--selftest" in sys.argv:
        print(wazuh_status())
        print(list_agents())
        print(top_rules(minutes=1440))
    else:
        mcp.run()
