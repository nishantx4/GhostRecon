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
                    ai_note = None
                    if self.ai and self.ai.enabled:
                        try:
                            ai_note = self.ai.analyze_graphql(url, resp.text)
                            if ai_note:
                                self.ui.ai(ai_note.split("\n")[0][:200])
                        except Exception:
                            pass

                    description = (
                        "GraphQL schema introspection is enabled in production, revealing "
                        "full API structure, types, and mutations."
                    )
                    if ai_note:
                        description += f"\n\nAI: most abusable surface:\n{ai_note.strip()}"

                    self.db.add(
                        title="GraphQL Introspection Enabled",
                        severity="high", url=url, module=self.NAME,
                        description=description,
                        remediation="Disable introspection in production. Use query depth limiting and query cost analysis.",
                        cvss="7.5", confidence="high",
                    )
                    self.ui.find("high", "GraphQL Introspection Enabled", url)
                    break
                time.sleep(self.delay)
            except Exception:
                continue


# ─── HTTP Smuggling Module ─────────────────────────────────────────────────────