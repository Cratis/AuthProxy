// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.given;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_logging_identity_resolution;

/// <summary>
/// Specifies that a legacy principal's raw provider-supplied user identifier never reaches a log sink.
/// <para>
/// Legacy is what every provider that has not opted into canonical identity resolves to, which is the
/// default — so "only legacy accounts disclose it" is not a narrow case, it is the common one.
/// </para>
/// </summary>
public class with_a_legacy_principal : an_identity_details_resolver_with_recorded_logs
{
    const string LegacyUserId = "sensitive-provider-subject";

    async Task Because() => await CreateResolver().Resolve(
        new DefaultHttpContext(),
        new ClientPrincipal { IdentityProvider = "legacy", UserId = LegacyUserId },
        TenantId);

    [Fact] void should_not_disclose_the_legacy_user_identifier() => _logger.Text.ShouldNotContain(LegacyUserId);
    [Fact] void should_still_record_the_bounded_reason() => _logger.Text.ShouldContain("legacy-account");
}
