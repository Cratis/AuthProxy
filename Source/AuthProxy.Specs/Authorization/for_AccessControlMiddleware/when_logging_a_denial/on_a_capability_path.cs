// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessControlMiddleware.when_logging_a_denial;

/// <summary>
/// Access control runs ahead of invite handling and sees the same paths, so a caller refused while following
/// an invitation link is refused on a path that <em>is</em> a live bearer capability. What the log needs is
/// which requirement was not met and roughly where — never the URL that would let a reader use the invitation.
/// </summary>
public class on_a_capability_path : given.an_access_control_middleware
{
    const string SensitiveCapability = "sensitive-capability-value";

    void Establish()
    {
        CallerCarrying(new Claim("urn:github:organization", "some-other-org"));
        _context.Request.Path = $"{WellKnownPaths.InvitePathPrefix}/{SensitiveCapability}";
        BuildMiddleware();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_disclose_the_capability() => _logger.Text.ShouldNotContain(SensitiveCapability);
    [Fact] void should_still_record_the_bounded_reason() => _logger.Text.ShouldContain("urn:github:organization");
    [Fact] void should_record_the_redacted_route() => _logger.Text.ShouldContain($"{WellKnownPaths.InvitePathPrefix}/[redacted]");
}
