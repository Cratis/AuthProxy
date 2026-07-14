// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

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
    /// The page returned when an authenticated user is not associated with any organization,
    /// so no tenant can be resolved for the request.
    /// </summary>
    public const string NoOrganization = "no-organization.html";

    /// <summary>
    /// The page returned when an invitation token is presented that has passed its expiry time.
    /// </summary>
    public const string InvitationExpired = "invitation-expired.html";

    /// <summary>
    /// The page returned when an invitation token is presented that is malformed or has an invalid signature.
    /// </summary>
    public const string InvitationInvalid = "invitation-invalid.html";

    /// <summary>
    /// The page returned when an authenticated user attempts to accept an invitation but the subject
    /// is already associated with an existing user.
    /// </summary>
    public const string InvitationSubjectAlreadyExists = "invitation-subject-already-exists.html";

    /// <summary>
    /// The page returned when an authenticated user attempts to accept an invitation with an account
    /// whose verified email does not match the email the invitation was issued for.
    /// </summary>
    public const string InvitationEmailMismatch = "invitation-email-mismatch.html";

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

    /// <summary>
    /// The page served when tenant selection is enabled and the authenticated user has no selected tenant.
    /// The page reads the <c>.cratis-tenants</c> cookie injected by the proxy and renders a selectable list.
    /// </summary>
    public const string SelectTenant = "select-tenant.html";

    /// <summary>
    /// The page served when an unauthenticated user reaches a lobby-mode proxy without a
    /// valid invitation token or pending invite cookie.
    /// </summary>
    public const string InvitationRequired = "invitation-required.html";
}
