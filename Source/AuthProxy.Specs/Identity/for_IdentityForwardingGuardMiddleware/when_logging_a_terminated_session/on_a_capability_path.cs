// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Identity.for_IdentityForwardingGuardMiddleware.when_logging_a_terminated_session;

/// <summary>
/// The guard terminates a session on whatever path the request happened to be on, including an invitation
/// path whose remainder is a live bearer capability. The route it happened on is worth recording; the
/// capability is not.
/// </summary>
public class on_a_capability_path : given.a_proxied_request
{
    const string SensitiveCapability = "sensitive-capability-value";

    void Establish()
    {
        SetAuthenticatedUser();
        _canonicalIdentityResolver
            .Resolve(Arg.Any<ClaimsPrincipal>(), Arg.Any<string?>(), Arg.Any<string?>(), Arg.Any<bool>())
            .Returns(CanonicalIdentityResolution.Failed());
        _context.Request.Path = $"{WellKnownPaths.InvitePathPrefix}/{SensitiveCapability}";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_disclose_the_capability() => _logger.Text.ShouldNotContain(SensitiveCapability);
    [Fact] void should_still_record_the_bounded_reason() => _logger.Text.ShouldContain("could not be turned into a forwardable identity");
    [Fact] void should_record_the_redacted_route() => _logger.Text.ShouldContain($"{WellKnownPaths.InvitePathPrefix}/[redacted]");
}
