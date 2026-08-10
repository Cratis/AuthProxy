// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy.given;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy;

/// <summary>
/// Trusting everyone deliberately behaves exactly like the fallback, and is reported as a decision rather
/// than as an omission — which is the whole difference between the two.
/// </summary>
public class when_every_peer_is_trusted_on_purpose : a_trusted_proxy_policy
{
    protected override C.Ingress Ingress => new() { Mode = C.TrustedProxyMode.TrustAny };

    [Fact] void should_trust_any_caller() => _policy.IsTrusted(IPAddress.Parse("198.51.100.10")).ShouldBeTrue();
    [Fact] void should_not_report_the_legacy_fallback() => _policy.IsLegacyAllowAll.ShouldBeFalse();
}
