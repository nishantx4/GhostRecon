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

        for path in gql_paths:
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                import json
                resp = s.post(url, json={"query": "{__schema{types{name}}}"}, timeout=self.timeout)
                if resp.status_code == 200 and "__schema" in resp.text:
                    self.db.add(
                        title="GraphQL Introspection Enabled",
                        severity="high", url=url, module=self.NAME,
                        description="GraphQL schema introspection is enabled in production, revealing full API structure, types, and mutations.",
                        remediation="Disable introspection in production. Use query depth limiting and query cost analysis.",
                        cvss="7.5", confidence="high",
                    )
                    self.ui.find("high", "GraphQL Introspection Enabled", url)
                    break
                time.sleep(self.delay)
            except Exception:
                continue


# ─── HTTP Smuggling Module ─────────────────────────────────────────────────────