// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Identifies the actual destination flow without retaining key material on the request.</summary>
/// <param name="Flow">The outbound flow.</param>
/// <param name="ServiceName">The routed service, or null for the tenant list.</param>
public sealed record ForwardedIdentitySigningTarget(ForwardedIdentityFlow Flow, string? ServiceName)
{
    /// <summary>The typed outbound-request target marker.</summary>
    public static readonly HttpRequestOptionsKey<ForwardedIdentitySigningTarget> OptionsKey = new("Cratis.AuthProxy.ForwardedIdentity.Target");
}
