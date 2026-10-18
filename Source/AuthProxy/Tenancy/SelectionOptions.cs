// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Options for the <see cref="SelectionSourceIdentifierStrategy"/>.
/// </summary>
public record SelectionOptions
{
    /// <summary>
    /// Gets the endpoint URL that returns the selectable tenant list for the authenticated user.
    /// </summary>
    public string TenantsEndpoint { get; init; } = string.Empty;

    /// <summary>
    /// Gets the audience of the signed forwarding assertion sent with the call to <see cref="TenantsEndpoint"/>.
    /// </summary>
    /// <remarks>
    /// Used only when signed forwarding is configured. When the endpoint is served by a configured service — its
    /// backend has the same scheme, host and port — that service's audience is used and this value is needed only
    /// to settle a tie between services sharing an origin. Otherwise it is required.
    /// </remarks>
    public string? ForwardingAudience { get; init; }
}
