// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ErrorPages;

/// <summary>
/// Holds the well-known file names for the custom error pages served by the ingress.
/// </summary>
public static class WellKnownPageNames
{
    /// <summary>
    /// The page returned when a requested resource is not found (HTTP 404).
    /// </summary>
    public const string NotFound = "404.html";

    /// <summary>
    /// The page returned when the caller is not authorized to access a resource (HTTP 403).
    /// </summary>
    public const string Forbidden = "403.html";

    /// <summary>
    /// The page returned when the resolved tenant does not exist in the system.
    /// </summary>
    public const string TenantNotFound = "tenant-not-found.html";

    /// <summary>
    /// The page returned when an invitation token is presented that has passed its expiry time.
    /// </summary>
    public const string InvitationExpired = "invitation-expired.html";

    /// <summary>
    /// The page returned when an invitation token is presented that is malformed or has an invalid signature.
    /// </summary>
    public const string InvitationInvalid = "invitation-invalid.html";

    /// <summary>
    /// The page served when a valid invitation token is presented and multiple identity providers
    /// are configured.  The page reads the <c>.cratis-providers</c> cookie injected by the proxy
    /// and renders a sign-in button for each available provider.
    /// </summary>
    public const string InvitationSelectProvider = "invitation-select-provider.html";

    /// <summary>
    /// The page served when an unauthenticated user reaches the proxy and multiple identity
    /// providers are configured.  The page reads the <c>.cratis-providers</c> cookie injected
    /// by the proxy and renders a sign-in button for each available provider.
    /// </summary>
    public const string SelectProvider = "select-provider.html";
}
