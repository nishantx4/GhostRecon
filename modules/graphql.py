"""
GraphQLModule — GhostRecon module.
"""
import re
import time
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from modules import BaseModule


class GraphQLModule(BaseModule):
    NAME = "GraphQL Probe"

    def run(self):
        self.ui.section("GraphQL — Introspection & Schema Analysis")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        gql_paths = ["/graphql", "/api/graphql", "/graphiql", "/gql", "/query", "/v1/graphql"]
        s = self._session()
        s.headers.update({"Content-Type": "application/json"})

        from core.validator import Validator
        validator = Validator()

        found = False
        for path in gql_paths:
            if found:
                break
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                import json
                
                # Check 1: Introspection
                resp = s.post(url, json={"query": "{__schema{types{name}}}"}, timeout=self.timeout)
                if resp.status_code == 200 and "__schema" in resp.text:
                    if validator.validate_json_schema(resp.text, {"data": {"__schema": dict}}):
                        self.db.add(
                            title="GraphQL Introspection Enabled",
                            severity="high", url=url, module=self.NAME,
                            description="GraphQL schema introspection is enabled in production, revealing full API structure, types, and mutations.",
                            remediation="Disable introspection in production. Use query depth limiting and query cost analysis.",
                            cvss="7.5", 
                            confidence="CONFIRMED",
                            confidence_score=95,
                            validation_steps=["status_200", "json_schema_match"]
                        )
                        self.ui.find("high", "GraphQL Introspection Enabled", url)
                        found = True
                        if url not in self.ctx.setdefault("endpoints", []):
                            self.ctx["endpoints"].append(url)
                        
                # Check 2: Aliased Batching (Query Denial of Service)
                batch_query = "{ " + " ".join([f"q{i}: __typename" for i in range(100)]) + " }"
                resp = s.post(url, json={"query": batch_query}, timeout=self.timeout)
                if resp.status_code == 200 and "q99" in resp.text:
                    if validator.validate_json_schema(resp.text, {"data": {"q99": str}}):
                        self.db.add(
                            title="GraphQL Aliased Query Batching (DoS)",
                            severity="medium", url=url, module=self.NAME,
                            description="GraphQL endpoint allows large aliased queries, which can be abused to bypass rate limits or cause server Denial of Service.",
                            remediation="Implement Query Depth Limiting, Query Cost Analysis, and limit the maximum number of aliases per query.",
                            cvss="5.3",
                            confidence="CONFIRMED",
                            confidence_score=90,
                            validation_steps=["status_200", "json_schema_match", "aliased_response_confirmed"]
                        )
                        self.ui.find("medium", "GraphQL Aliased Batching", url)
                        found = True
                        if url not in self.ctx.setdefault("endpoints", []):
                            self.ctx["endpoints"].append(url)
                        
                # Check 3: Array Batching
                array_batch = [{"query": "{__typename}"} for _ in range(10)]
                resp = s.post(url, json=array_batch, timeout=self.timeout)
                if resp.status_code == 200 and resp.text.startswith("[") and "__typename" in resp.text:
                    self.db.add(
                        title="GraphQL Array Batching Enabled",
                        severity="medium", url=url, module=self.NAME,
                        description="GraphQL endpoint processes arrays of queries in a single request. This allows bypassing standard rate limits for brute force attacks (e.g. against login mutations).",
                        remediation="Disable array-based query batching if not required, or ensure rate limiting applies to the total number of operations, not just HTTP requests.",
                        cvss="5.3",
                        confidence="CONFIRMED",
                        confidence_score=90,
                        validation_steps=["status_200", "json_array_response", "typename_found"]
                    )
                    self.ui.find("medium", "GraphQL Array Batching", url)
                    found = True
                    if url not in self.ctx.setdefault("endpoints", []):
                        self.ctx["endpoints"].append(url)

                time.sleep(self.delay)
            except Exception:
                continue


# ─── HTTP Smuggling Module ─────────────────────────────────────────────────────