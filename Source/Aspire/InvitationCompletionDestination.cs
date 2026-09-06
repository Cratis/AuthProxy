// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

/// <summary>
/// Determines where the browser is redirected after a successfully completed invitation whose tenant claim
/// matches the resolved tenant.
/// </summary>
/// <remarks>
/// This setting changes only the post-completion redirect choice. It does not change invitation staging,
/// completion, tenant matching, recipient binding, attestations, transactions, cookies, or sessions.
/// <para>
/// Matching-tenant invitations are those where the configured <c>TenantClaim</c> value in the invitation
/// capability equals the tenant resolved for the request. The equality does not prove that the invitation
/// was issued by that tenant — any issuer holding the signing key can write that claim. It proves only
/// that the invitation names the tenant the request is being served for, which is enough to know whether
/// the browser should stay in the tenant's own surface or continue through Lobby.
/// </para>
/// </remarks>
public enum InvitationCompletionDestination
{
    /// <summary>
    /// The browser continues toward the invitation challenge's return URL instead of selecting the configured
    /// Lobby frontend. This is the default and preserves the released behavior.
    /// </summary>
    ReturnUrl = 0,

    /// <summary>
    /// The browser is redirected to the configured Lobby frontend, the same as nonmatching or unresolved
    /// invitations.
    /// </summary>
    Lobby = 1,
}
