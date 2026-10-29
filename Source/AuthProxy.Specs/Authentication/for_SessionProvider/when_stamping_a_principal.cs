// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SessionProvider;

/// <summary>
/// Specifies that stamping records the provider scheme as one claim.
/// </summary>
public class when_stamping_a_principal : Specification
{
    ClaimsPrincipal _principal;
    AuthenticationProperties _properties;

    void Establish()
    {
        _principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-42")], "AuthenticationTypes.Federation"));
        _properties = new AuthenticationProperties();
    }

    void Because() => SessionProvider.Stamp(_principal, _properties, "microsoft");

    [Fact] void should_add_exactly_one_session_claim() => _principal.Claims.Count(_ => SessionClaims.IsReserved(_.Type)).ShouldEqual(1);
    [Fact] void should_record_the_scheme() => _principal.FindFirst(SessionClaims.ProviderScheme)!.Value.ShouldEqual("microsoft");
    [Fact] void should_record_the_marker_in_the_session_properties() => _properties.Items[SessionProvider.MarkerStateKey].ShouldEqual("microsoft");
    [Fact] void should_keep_the_other_claims() => _principal.FindFirst("sub")!.Value.ShouldEqual("user-42");
}
