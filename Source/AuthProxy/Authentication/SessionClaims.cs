// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Defines the claim type identifiers AuthProxy reserves for metadata it records on a browser session.
/// </summary>
/// <remarks>
/// AuthProxy removes any claim in this namespace supplied by a provider before it records its own value when a
/// sign-in completes. Only explicitly enabled session-context claims are forwarded to applications.
/// </remarks>
public static class SessionClaims
{
    /// <summary>
    /// The claim type for the authentication scheme of the provider the session was signed in with.
    /// </summary>
    public const string ProviderScheme = "urn:cratis:session:provider-scheme";

    /// <summary>The Unix time of the authentication recorded by AuthProxy.</summary>
    public const string AuthenticationTime = "urn:cratis:session:auth_time";

    /// <summary>The original session start forwarded in Unix seconds when enabled for a service.</summary>
    public const string Started = "urn:cratis:session:started";

    /// <summary>The sign-in provider scheme forwarded when enabled for a service.</summary>
    public const string SignInProvider = "urn:cratis:session:sign-in-provider";

    /// <summary>Determines whether a type is reserved for forwarded session context.</summary>
    /// <param name="claimType">The claim type to inspect.</param>
    /// <returns>Whether the type is one of the two AuthProxy-authored forwarded claims.</returns>
    public static bool IsForwardedSessionContext(string claimType) =>
        string.Equals(claimType, Started, StringComparison.OrdinalIgnoreCase)
        || string.Equals(claimType, SignInProvider, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Determines whether a claim type belongs to the namespace reserved for AuthProxy-authored session metadata.
    /// </summary>
    /// <param name="claimType">The claim type to inspect.</param>
    /// <returns><see langword="true"/> when <paramref name="claimType"/> is in the reserved namespace; otherwise <see langword="false"/>.</returns>
    public static bool IsReserved(string claimType) =>
        claimType.StartsWith("urn:cratis:session:", StringComparison.OrdinalIgnoreCase);
}
