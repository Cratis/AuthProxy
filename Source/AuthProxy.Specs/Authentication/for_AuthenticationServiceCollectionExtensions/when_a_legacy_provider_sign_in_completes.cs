// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a provider without canonical identity also records its provider scheme on the session.
/// </summary>
public class when_a_legacy_provider_sign_in_completes : canonical_cookie_registration
{
    async Task Because()
    {
        UseAuthentication(LegacyProviderAuthentication());
        await IssueCanonicalTicket();
    }

    [Fact] void should_not_have_canonical_claims() => _issuedPrincipal!.Claims.Any(_ => CanonicalIdentityClaims.IsReserved(_.Type)).ShouldBeFalse();
    [Fact] void should_record_exactly_one_provider_scheme() => _issuedPrincipal!.FindAll(SessionClaims.ProviderScheme).Count().ShouldEqual(1);
    [Fact] void should_record_the_scheme() => _issuedPrincipal!.FindFirst(SessionClaims.ProviderScheme)!.Value.ShouldEqual(ProviderScheme);

    static C.Authentication LegacyProviderAuthentication() => new()
    {
        OidcProviders = [new C.OidcProvider { Name = "Microsoft", Authority = "https://login.example.com/common/v2.0", ClientId = "registration-client", ClientSecret = ClientSecret }]
    };
}
