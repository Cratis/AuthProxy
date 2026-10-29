// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Defines the claim type identifiers AuthProxy reserves for metadata it records on a browser session.
/// </summary>
/// <remarks>
/// AuthProxy removes any claim in this namespace supplied by a provider before it records its own value when a
/// sign-in completes. The claim is never forwarded to applications.
/// </remarks>
public static class SessionClaims
{
    /// <summary>
    /// The claim type for the authentication scheme of the provider the session was signed in with.
    /// </summary>
    public const string ProviderScheme = "urn:cratis:session:provider-scheme";

    /// <summary>
    /// Determines whether a claim type belongs to the namespace reserved for AuthProxy-authored session metadata.
    /// </summary>
    /// <param name="claimType">The claim type to inspect.</param>
    /// <returns><see langword="true"/> when <paramref name="claimType"/> is in the reserved namespace; otherwise <see langword="false"/>.</returns>
    public static bool IsReserved(string claimType) =>
        claimType.StartsWith("urn:cratis:session:", StringComparison.OrdinalIgnoreCase);
}
