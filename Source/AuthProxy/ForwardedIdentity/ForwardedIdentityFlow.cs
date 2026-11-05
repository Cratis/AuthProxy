// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Identifies an outbound forwarded-identity flow.</summary>
public enum ForwardedIdentityFlow
{
    /// <summary>A regular proxied request.</summary>
    ProxiedRequest = 0,

    /// <summary>A request authenticated by a bearer route.</summary>
    BearerRoute = 1,

    /// <summary>An identity-details back-channel call.</summary>
    IdentityDetails = 2,

    /// <summary>A selected-tenant list back-channel call.</summary>
    TenantList = 3
}
