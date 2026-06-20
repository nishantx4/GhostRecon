"""
SSTIModule — Server-Side Template Injection detection.

Injects arithmetic-marker payloads (e.g. {{7*7}} -> 49) across common
template engines (Jinja2, Twig, Freemarker, Velocity, ERB, Smarty) and
confirms only when the rendered arithmetic result appears in the response
but the raw expression does not. This keeps false positives low: a result
that is merely reflected verbatim is not template injection.
"""
import re
import time
import uuid
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from modules import BaseModule


# Each probe carries the raw expression and the expected rendered output.
# Two random factors make the product unlikely to collide with page content.
def _build_probes():
    a, b = 7331, 13   # distinctive factors -> 95303
    product = a * b
    return [
        (f"{{{{{a}*{b}}}}}", str(product)),       # Jinja2 / Twig  {{7331*13}}
        (f"${{{a}*{b}}}",    str(product)),        # Freemarker / JSP EL  ${...}
        (f"#{{{a}*{b}}}",    str(product)),        # Ruby / Velocity-ish  #{...}
        (f"*{{{a}*{b}}}",    str(product)),        # Thymeleaf  *{...}
        (f"{{{a}*{b}}}",     str(product)),        # Smarty  {7331*13}
        (f"<%= {a}*{b} %>",  str(product)),        # ERB
    ]


INJECT_PARAMS = ["q", "search", "s", "name", "id", "page", "query", "input",
                 "message", "comment", "title", "template", "tpl", "view",
                 "lang", "locale", "redirect", "email", "user"]


class SSTIModule(BaseModule):
    NAME = "SSTI"

    def run(self):
        self.ui.section("SSTI — Server-Side Template Injection Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        self.session = self._session()
        self.probes  = _build_probes()
        targets = self._collect_targets()
        self.ui.info(f"Testing {len(targets)} injection point(s) for SSTI")

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._test, url, param): (url, param)
                       for url, param in targets}
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    if self.verbose:
                        self.ui.error(f"SSTI thread error: {e}")

    def _collect_targets(self):
        targets = []
        seen = set()

        for ep in self.ctx.get("endpoints", []):
            try:
                parsed = urllib.parse.urlparse(ep)
                base = parsed.scheme + "://" + parsed.netloc + parsed.path
                for param in urllib.parse.parse_qs(parsed.query):
                    key = (base, param)
                    if key not in seen:
                        seen.add(key)
                        targets.append(key)
            except Exception:
                continue

        for param in INJECT_PARAMS:
            key = (self.base_url, param)
            if key not in seen:
                seen.add(key)
                targets.append(key)

        return targets

    def _test(self, url, param):
        for expr, expected in self.probes:
            try:
                resp = self.session.get(url, params={param: expr}, timeout=self.timeout)
            except Exception:
                continue
            if not resp:
                continue

            body = resp.text
            # Confirmed only if the rendered result is present AND the raw
            # expression is NOT (otherwise it is plain reflection).
            if expected in body and expr not in body:
                self._report(url, param, expr, expected)
                return
            time.sleep(self.delay)

    def _report(self, url, param, expr, expected):
        poc = f"{url}?{urllib.parse.urlencode({param: expr})}"
        self.db.add(
            title=f"Server-Side Template Injection in '{param}'",
            severity="critical", url=url, module=self.NAME,
            description=(
                f"The '{param}' parameter evaluates template expressions server-side. "
                f"Payload `{expr}` rendered to `{expected}`, proving the expression was "
                "executed rather than reflected. SSTI commonly escalates to remote code "
                "execution depending on the template engine."
            ),
            remediation=(
                "Never pass user input into template engines as template code. Use a "
                "sandboxed/logic-less template, render data only through context variables, "
                "and validate/escape all user input."
            ),
            cvss="9.8", confidence="high",
            evidence=[f"Payload: {expr}", f"Rendered: {expected}", f"PoC: {poc}"],
            references=[
                "https://portswigger.net/web-security/server-side-template-injection",
            ],
        )
        self.ui.find("critical", f"SSTI in '{param}'", url)
        self.ui.bullet(f"Payload {expr} rendered to {expected}", indent=12)
