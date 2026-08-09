// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that every provider-registration component binds a canonical cookie ticket to the registration that issued it.
/// </summary>
public class when_validating_a_canonical_cookie_ticket_after_its_registration_changes : canonical_cookie_registration
{
    readonly Dictionary<string, bool> _acceptedByChange = [];

    async Task Because()
    {
        var properties = await IssueCanonicalTicket();
        var originalMetadataAddress = _oidcOptions.MetadataAddress;

        UseAuthentication(InitialAuthentication(authority: "https://login.example.com/organizations/v2.0"));
        _acceptedByChange["OIDC authority"] = await IsAccepted(CanonicalPrincipal(), properties);

        UseAuthentication(InitialAuthentication());
        _oidcOptions.MetadataAddress = "https://metadata.example.com/.well-known/openid-configuration";
        _acceptedByChange["effective discovery source"] = await IsAccepted(CanonicalPrincipal(), properties);
        _oidcOptions.MetadataAddress = originalMetadataAddress;

        UseAuthentication(InitialAuthentication(clientId: "different-client"));
        _acceptedByChange["client ID"] = await IsAccepted(CanonicalPrincipal(), properties);

        UseAuthentication(InitialAuthentication(subjectClaimType: "sub"));
        _acceptedByChange["subject claim type"] = await IsAccepted(CanonicalPrincipal(), properties);

        UseAuthentication(InitialAuthentication(providerKey: "different-workforce"));
        _acceptedByChange["provider key"] = await IsAccepted(CanonicalPrincipal(), properties);

        UseAuthentication(OAuthAuthentication());
        _acceptedByChange["provider protocol"] = await IsAccepted(CanonicalPrincipal(), properties);

        UseAuthentication(InitialAuthentication(name: "Microsoft Workforce"));
        _acceptedByChange["provider scheme"] = await IsAccepted(CanonicalPrincipal(), properties);
    }

    [Fact]
    void should_reject_every_changed_registration()
    {
        foreach (var result in _acceptedByChange)
        {
            Assert.False(result.Value, $"The ticket was accepted after changing {result.Key}.");
        }
    }
}
