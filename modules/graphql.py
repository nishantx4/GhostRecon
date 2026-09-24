"""
GraphQLModule — GhostRecon module.
"""
import json
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

        found = False
        for path in gql_paths:
            if found:
                break
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                # Check 1: Introspection. NOTE: this previously called
                # Validator.validate_json_schema(), a method that has never
                # existed on core.validator.Validator — every hit raised
                # AttributeError, which the broad except below silently
                # swallowed, so this check has never fired a single finding.
                # Replaced with direct, correct JSON parsing.
                resp = s.post(url, json={"query": "{__schema{types{name}}}"}, timeout=self.timeout)
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                    except ValueError:
                        body = None
                    schema = (body or {}).get("data", {}).get("__schema") if isinstance(body, dict) else None
                    if isinstance(schema, dict) and schema.get("types"):
                        type_names = [t.get("name") for t in schema["types"] if isinstance(t, dict) and t.get("name")]
                        self.db.add(
                            title="GraphQL Introspection Enabled",
                            severity="high", url=url, module=self.NAME,
                            description=(
                                "GraphQL schema introspection is enabled in production, revealing the full "
                                f"API structure: {len(type_names)} type(s) discovered, including "
                                f"{', '.join(type_names[:10])}{'…' if len(type_names) > 10 else ''}."
                            ),
                            remediation="Disable introspection in production. Use query depth limiting and query cost analysis.",
                            cvss="7.5",
                            confidence="CONFIRMED",
                            confidence_score=95,
                            evidence=[f"{len(type_names)} types exposed via introspection"],
                            validation_steps=["status_200", "valid_json", "__schema_types_present"],
                        )
                        self.ui.find("high", "GraphQL Introspection Enabled", url)
                        found = True
                        if url not in self.ctx.setdefault("endpoints", []):
                            self.ctx["endpoints"].append(url)

                # Check 2: Aliased Batching (Query Denial of Service)
                batch_query = "{ " + " ".join([f"q{i}: __typename" for i in range(100)]) + " }"
                resp = s.post(url, json={"query": batch_query}, timeout=self.timeout)
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                    except ValueError:
                        body = None
                    data = (body or {}).get("data") if isinstance(body, dict) else None
                    if isinstance(data, dict) and "q99" in data:
                        self.db.add(
                            title="GraphQL Aliased Query Batching (DoS)",
                            severity="medium", url=url, module=self.NAME,
                            description="GraphQL endpoint allows large aliased queries (100 aliases accepted in one request), which can be abused to bypass rate limits or cause server Denial of Service.",
                            remediation="Implement Query Depth Limiting, Query Cost Analysis, and limit the maximum number of aliases per query.",
                            cvss="5.3",
                            confidence="CONFIRMED",
                            confidence_score=90,
                            validation_steps=["status_200", "valid_json", "all_100_aliases_resolved"],
                        )
                        self.ui.find("medium", "GraphQL Aliased Batching", url)
                        found = True
                        if url not in self.ctx.setdefault("endpoints", []):
                            self.ctx["endpoints"].append(url)

                # Check 3: Array Batching
                array_batch = [{"query": "{__typename}"} for _ in range(10)]
                resp = s.post(url, json=array_batch, timeout=self.timeout)
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                    except ValueError:
                        body = None
                    if (isinstance(body, list) and len(body) >= 2
                            and all(isinstance(item, dict) and "data" in item for item in body)):
                        self.db.add(
                            title="GraphQL Array Batching Enabled",
                            severity="medium", url=url, module=self.NAME,
                            description=f"GraphQL endpoint processed an array of {len(body)} queries in a single request. This allows bypassing standard per-request rate limits for brute force attacks (e.g. against login mutations).",
                            remediation="Disable array-based query batching if not required, or ensure rate limiting applies to the total number of operations, not just HTTP requests.",
                            cvss="5.3",
                            confidence="CONFIRMED",
                            confidence_score=90,
                            validation_steps=["status_200", "valid_json_array", "per_item_data_present"],
                        )
                        self.ui.find("medium", "GraphQL Array Batching", url)
                        found = True
                        if url not in self.ctx.setdefault("endpoints", []):
                            self.ctx["endpoints"].append(url)

                time.sleep(self.delay)
            except Exception:
                continue

        if not found:
            self.ui.info("No GraphQL endpoint / vulnerabilities found.")


# ─── HTTP Smuggling Module ─────────────────────────────────────────────────────