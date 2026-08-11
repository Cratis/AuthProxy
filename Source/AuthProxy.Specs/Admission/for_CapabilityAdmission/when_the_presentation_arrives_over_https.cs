// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityAdmission;

/// <summary>
/// The entry transaction is marked <c>Secure</c> whenever the request itself is encrypted — which behind a
/// TLS-terminating ingress is what the forwarded headers have already made it say.
/// </summary>
public class when_the_presentation_arrives_over_https : given.a_capability_admission
{
    void Establish()
    {
        _context.Request.Scheme = "https";
        Presenting(Capability);
        VerifierAdmitting();
    }

    async Task Because() => _admitted = await _admission.TryAdmit(_context, _config);

    [Fact] void should_mark_the_cookie_secure() => IssuedCookieHeader().Contains("secure", StringComparison.OrdinalIgnoreCase).ShouldBeTrue();
}
