// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the access token AuthProxy obtains for the signed-in user and forwards to a service's backend.
/// </summary>
/// <remarks>
/// AuthProxy acts as a backend for frontend: it redeems the refresh token it holds server-side for the user's
/// session at the identity provider's token endpoint, asking for <see cref="Scopes"/> (and <see cref="Resource"/>
/// when set), and forwards the resulting access token as <c language="text">Authorization: Bearer</c>. The refresh token never
/// leaves AuthProxy, and the ID token is never forwarded.
/// </remarks>
public class ServiceAccessToken
{
    /// <summary>
    /// Gets or sets the scopes to request for the backend's audience, for example
    /// <c language="text">api://reporting/access_as_user</c> for Microsoft Entra ID.
    /// </summary>
    public IList<string> Scopes { get; set; } = [];

    /// <summary>
    /// Gets or sets an optional resource indicator (RFC 8707) to request the token for, for identity providers that
    /// select the audience with the <c language="text">resource</c> parameter rather than scopes.
    /// </summary>
    public string Resource { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the name of the OIDC provider the token must come from. When empty, the token comes from the
    /// provider the user signed in with. When set, a user signed in with another provider gets no token, and the
    /// request is refused.
    /// </summary>
    public string Provider { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the server-selected backend destination binding for access-token caching.
    /// This is assigned from the matched proxy cluster, never from configuration or caller input.
    /// </summary>
    internal string DestinationBinding { get; set; } = string.Empty;
}
