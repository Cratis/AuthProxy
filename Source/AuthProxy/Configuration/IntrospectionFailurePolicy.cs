// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents what a bearer route does with a token whose issuer's introspection endpoint could not be asked.
/// </summary>
/// <remarks>
/// Only applies when the token's issuer has <see cref="BearerIssuer.Introspection"/> configured. A reachable
/// endpoint that answers that the token is not active always refuses it, whatever this says.
/// </remarks>
public enum IntrospectionFailurePolicy
{
    /// <summary>
    /// Refuse the request with <c language="text">503</c>. The default, and the only value accepted on an MCP route.
    /// </summary>
    Refuse = 0,

    /// <summary>
    /// Accept the token on its local validation alone and log a warning. Revocation is not enforced while the
    /// endpoint is unavailable.
    /// </summary>
    Accept = 1,
}
