// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SessionProvider;

/// <summary>
/// Specifies that a marker value already present in the properties never survives the stamp.
/// </summary>
public class when_stamping_over_a_marker_supplied_before_sign_in : Specification
{
    AuthenticationProperties _properties;

    void Establish() => _properties = new AuthenticationProperties(new Dictionary<string, string?> { [SessionProvider.MarkerStateKey] = "github" });

    void Because() => SessionProvider.Stamp(new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-42")], "x")), _properties, "microsoft");

    [Fact] void should_hold_the_completing_scheme() => _properties.Items[SessionProvider.MarkerStateKey].ShouldEqual("microsoft");
}
