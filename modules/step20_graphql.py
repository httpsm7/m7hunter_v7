import os
#!/usr/bin/env python3
# modules/step20_graphql.py — GraphQL Security Testing
# MilkyWay Intelligence | Author: Sharlix

import json
from core.utils import safe_read
from core.http_client import sync_post, sync_get

GRAPHQL_PATHS = [
    "/graphql","/api/graphql","/graphql/v1","/v1/graphql",
    "/api/v1/graphql","/api/v2/graphql","/query","/gql",
    "/graphiql","/playground",
]

INTROSPECTION_QUERY = """
{
  __schema {
    types { name fields { name type { name kind ofType { name kind } } } }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
""".strip()

BATCH_QUERY_TEMPLATE = """[
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"}
]"""

DANGEROUS_TYPE_PATTERNS = [
    "password","secret","token","apikey","credit_card",
    "ssn","private","internal","admin","root",
]



def _get_live_hosts(p, limit=100):
    """Returns live hosts - ALWAYS includes main target as fallback."""
    tgt = p.target.strip()
    if not tgt.startswith("http"):
        tgt = "https://" + tgt

    hosts = []
    seen  = set()

    for key in ("fmt_url", "live_hosts", "resolved"):
        src = p.files.get(key, "")
        if not src or not os.path.isfile(src):
            continue
        from core.utils import safe_read
        for line in safe_read(src):
            line = line.strip()
            if not line:
                continue
            if not line.startswith("http"):
                line = "https://" + line
            if line not in seen:
                seen.add(line)
                hosts.append(line)
        if hosts:
            break

    # GUARANTEED: always include main target
    if tgt not in seen:
        hosts.insert(0, tgt)

    return hosts[:limit]


class Step20Graphql:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files["graphql_results"]
        live  = safe_read(p.files.get("fmt_url",""))[:100]
        found = 0

        if not live:
            p.log.warn("GraphQL: no live hosts"); return

        p.log.info("GraphQL security testing")
        auth_h = {}
        if getattr(p.args,"cookie",None):
            auth_h["Cookie"] = p.args.cookie

        for host in live:
            host = host.rstrip("/")
            for path in GRAPHQL_PATHS:
                url = host + path
                resp = sync_get(url, headers=auth_h, timeout=6)
                if not resp or resp.get("status",0) not in (200,400,405):
                    continue

                body = resp.get("body","").lower()
                if "graphql" not in body and "query" not in body and resp.get("status") == 200:
                    continue

                p.log.info(f"  GraphQL endpoint: {url}")

                # Test 1: Introspection
                intro_resp = sync_post(
                    url, json_data={"query": INTROSPECTION_QUERY},
                    headers={**auth_h,"Content-Type":"application/json"}, timeout=10
                )
                if intro_resp and intro_resp.get("status",0) == 200:
                    try:
                        data = json.loads(intro_resp.get("body",""))
                        if "data" in data and "__schema" in str(data):
                            detail = f"GraphQL introspection enabled — full schema exposed at {url}"
                            with open(out,"a") as f:
                                f.write(f"GRAPHQL_INTROSPECTION: {url} | {detail}\n")
                            p.add_finding("high","GRAPHQL_INTROSPECTION",url,detail,"graphql")
                            found += 1

                            # Check for sensitive fields in schema
                            schema_str = str(data).lower()
                            for pattern in DANGEROUS_TYPE_PATTERNS:
                                if pattern in schema_str:
                                    p.add_finding("high","GRAPHQL_SENSITIVE_FIELDS",
                                        url, f"Sensitive field '{pattern}' in schema","graphql")

                    except json.JSONDecodeError:
                        pass

                # Test 2: Batch query attack
                batch_resp = sync_post(
                    url, json_data=None,
                    headers={**auth_h,"Content-Type":"application/json"}, timeout=8
                )
                # Try raw batch
                import urllib.request
                try:
                    req = urllib.request.Request(
                        url, data=BATCH_QUERY_TEMPLATE.encode(),
                        headers={**auth_h,"Content-Type":"application/json"},
                        method="POST"
                    )
                    r = urllib.request.urlopen(req, timeout=8)
                    body2 = r.read(5000).decode("utf-8","ignore")
                    if isinstance(body2, str) and body2.startswith("[") and "data" in body2:
                        detail = f"GraphQL batching enabled — rate limit bypass possible"
                        with open(out,"a") as f:
                            f.write(f"GRAPHQL_BATCH: {url} | {detail}\n")
                        p.add_finding("medium","GRAPHQL_BATCH_ATTACK",url,detail,"graphql")
                        found += 1
                except Exception as _e:
                    pass
                except Exception as _e:
                    pass
                    from core.error_handler import get_handler
                    get_handler().capture("step20_graphql", _e)

                # Test 3: GraphiQL IDE exposed
                if "graphiql" in body or "playground" in body:
                    detail = f"GraphQL IDE exposed (GraphiQL/Playground) at {url}"
                    p.add_finding("medium","GRAPHQL_IDE_EXPOSED",url,detail,"graphql")
                    found += 1

                break  # found endpoint on this host

        p.log.success(f"GraphQL: {found} findings")
    def _test_batching(self, endpoint):
        """Blueprint Fix: GraphQL query batching abuse (rate limit bypass)."""
        import json, urllib.request
        batch = [{"query":"{ __typename }"}] * 20
        try:
            data = json.dumps(batch).encode()
            req  = urllib.request.Request(endpoint, data=data,
                   headers={"Content-Type":"application/json","User-Agent":"M7Hunter/7.0"})
            resp = urllib.request.urlopen(req, timeout=15)
            body = resp.read(5000).decode(errors="ignore")
            if body.startswith("[") and '"__typename"' in body:
                self.p.add_finding("medium","GRAPHQL_BATCHING_ABUSE",endpoint,
                    "Batched queries accepted without rate limiting","graphql",
                    confidence=0.80,status="confirmed")
        except Exception as e:
            from core.error_handler import get_handler; get_handler().capture("step20_graphql",e,"batching")

    def _test_field_suggestion(self, endpoint):
        """Blueprint Fix: Field suggestion attack — enumerate hidden fields."""
        import json, urllib.request
        typo_queries = [
            '{"query":"{usr{id}}"}',
            '{"query":"{admin{id}}"}',
            '{"query":"{pasword}"}',
            '{"query":"{tok{id}}"}',
        ]
        suggested = []
        for q in typo_queries:
            try:
                req = urllib.request.Request(endpoint, data=q.encode(),
                      headers={"Content-Type":"application/json","User-Agent":"M7Hunter/7.0"})
                resp = urllib.request.urlopen(req, timeout=10)
                body = resp.read(2000).decode(errors="ignore")
                import re
                m = re.search(r"Did you mean.*?([a-z_]+)", body, re.IGNORECASE)
                if m: suggested.append(m.group(1))
            except Exception as _e:
                pass
            except Exception as _e:
                pass
                from core.error_handler import get_handler
                get_handler().capture("step20_graphql", _e)
        if suggested:
            self.p.add_finding("low","GRAPHQL_FIELD_SUGGESTION",endpoint,
                f"Field suggestion enabled — discovered: {suggested[:5]}","graphql",
                confidence=0.70)

