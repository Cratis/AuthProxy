// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies the persistent registration state produced when a canonical provider callback completes.
/// </summary>
public class when_completing_a_canonical_provider_ticket : canonical_cookie_registration
{
    const string TransientValidatedIssuerStateKey = "Cratis.AuthProxy.ValidatedIssuer";
    AuthenticationProperties _properties;

    async Task Because() => _properties = await IssueCanonicalTicket();

    [Fact] void should_carry_a_version_one_registration_fingerprint() =>
        _properties.Items.Values.Any(_ => _?.StartsWith("v1:", StringComparison.Ordinal) == true).ShouldBeTrue();
    [Fact] void should_not_carry_the_raw_client_secret() =>
        _properties.Items.Values.Any(_ => _?.Contains(ClientSecret, StringComparison.Ordinal) == true).ShouldBeFalse();
    [Fact] void should_remove_the_transient_validated_issuer_state() =>
        _properties.Items.ContainsKey(TransientValidatedIssuerStateKey).ShouldBeFalse();
}
