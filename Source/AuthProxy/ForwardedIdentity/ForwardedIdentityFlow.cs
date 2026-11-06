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
    TenantList = 3,

    /// <summary>A sign-in callback carrying identity headers.</summary>
    SignInCallback = 4,

    /// <summary>An on-behalf call protected by its per-call attestation, not the header envelope.</summary>
    OnBehalf = 5,

    /// <summary>Invitation staging, reported for transport only; body identity uses the flow's own attestation, not the header envelope.</summary>
    InvitationStage = 6,

    /// <summary>Invitation exchange, reported for transport only; body identity uses the flow's own attestation, not the header envelope.</summary>
    InvitationExchange = 7,

    /// <summary>Link exchange, reported for transport only; body identity is not covered by the header envelope.</summary>
    LinkExchange = 8,

    /// <summary>Sign-in notification, reported for transport only; body identity uses the flow's own attestation, not the header envelope.</summary>
    SignInNotification = 9
}
