// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.given;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_logging_identity_resolution;

/// <summary>
/// Specifies that legacy user identifiers remain available as released diagnostic context.
/// </summary>
public class with_a_legacy_principal : an_identity_details_resolver_with_recorded_logs
{
    const string LegacyUserId = "legacy-user-42";

    async Task Because() => await CreateResolver().Resolve(
        new DefaultHttpContext(),
        new ClientPrincipal { IdentityProvider = "legacy", UserId = LegacyUserId },
        TenantId);

    [Fact] void should_preserve_the_legacy_user_identifier_diagnostic() => string.Join(Environment.NewLine, _logger.Messages).ShouldContain(LegacyUserId);
}
