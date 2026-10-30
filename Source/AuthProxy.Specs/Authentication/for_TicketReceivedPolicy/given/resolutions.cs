// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy.given;

/// <summary>
/// Provides canonical identity resolutions and ticket properties for ticket routing specifications.
/// </summary>
public class resolutions : Specification
{
    internal static CanonicalIdentityResolution Legacy() => CanonicalIdentityResolution.Legacy(new ClaimsPrincipal());

    internal static CanonicalIdentityResolution Failed() => CanonicalIdentityResolution.Failed();

    internal static CanonicalIdentityResolution Success() => CanonicalIdentityResolution.Success(
        new CanonicalFederatedIdentity("provider", "https://issuer.example.com", "subject"),
        new ClaimsPrincipal());

    protected static AuthenticationProperties LinkProperties(string value = "true")
    {
        var properties = new AuthenticationProperties();
        properties.Items[LinkMiddleware.LinkModePropertyKey] = value;
        return properties;
    }
}
