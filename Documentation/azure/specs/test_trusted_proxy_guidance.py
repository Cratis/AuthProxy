# Copyright (c) Cratis. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.

"""Guard the Container Apps recipe's documented forwarded-header trust boundary."""

from pathlib import Path
import re
import unittest


class TrustedProxyGuidanceSpecs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).parents[1]
        cls.overview = (root / "index.md").read_text()
        cls.container_apps = (root / "container-apps.md").read_text()
        cls.upstream = cls.container_apps.split("### Adding an upstream proxy\n", 1)[1].split("### Health probes", 1)[0]
        cls.upstream = " ".join(cls.upstream.split())

    def test_public_container_apps_recipe_consumes_only_the_platform_supplied_address(self):
        recipe = re.search(r"```bash\n(az containerapp create.*?)\n```", self.container_apps, re.S)
        self.assertIsNotNone(recipe)
        self.assertIn("--ingress external", recipe.group(1))
        self.assertIn("Cratis__AuthProxy__Ingress__Mode=TrustAny", recipe.group(1))
        self.assertIn("Cratis__AuthProxy__Ingress__ForwardLimit=1", recipe.group(1))

    def test_overview_qualifies_extra_hops_for_the_trust_any_recipe(self):
        guidance = " ".join(self.overview.split())
        self.assertIn("keep `ForwardLimit=1` unless access to AuthProxy's origin is restricted to the intended upstream proxy", guidance)
        self.assertIn("`TrustAny` ignores that list", guidance)
        self.assertIn("use `Configured` mode with verified trusted hops", guidance)
        self.assertIn("[direct-origin spoofed-header check](container-apps.md#adding-an-upstream-proxy)", guidance)

    def test_increasing_the_limit_requires_an_origin_boundary_or_verified_configured_hops(self):
        self.assertIn("Keep `ForwardLimit=1` while that origin is publicly reachable in `Mode=TrustAny`", self.upstream)
        self.assertIn("Restrict access to AuthProxy's origin to the intended upstream proxy", self.upstream)
        self.assertIn("including any routes from other apps in the environment", self.upstream)
        self.assertIn("Use `Mode=Configured` with verified trusted hops in `TrustedProxies`", self.upstream)
        self.assertIn("including the actual Container Apps ingress peer and the upstream proxy", self.upstream)
        self.assertIn("Adding upstream ranges to `TrustedProxies` cannot prevent this in `TrustAny` mode", self.upstream)

    def test_direct_origin_spoof_check_is_required_before_a_higher_limit_is_deployed(self):
        self.assertIn("Require a direct-origin spoofed-header check before increasing `ForwardLimit`", self.upstream)
        self.assertIn("send `X-Forwarded-For: 203.0.113.123` directly to AuthProxy's ACA origin hostname", self.upstream)
        self.assertIn("the platform must refuse that request before it reaches AuthProxy", self.upstream)
        self.assertIn("records the actual caller address, never `203.0.113.123`", self.upstream)
        self.assertIn("a normal sign-in through the upstream proxy records the real client address", self.upstream)
        self.assertIn("Test the proposed higher limit in a non-production deployment with the same boundary", self.upstream)
        self.assertIn("do not increase it if the check fails or the recorded address cannot be observed", self.upstream)


if __name__ == "__main__":
    unittest.main()
