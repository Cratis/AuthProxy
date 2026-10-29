// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents the answer to one grant check.
/// </summary>
/// <param name="Status">What the check established.</param>
/// <param name="ValidUntil">When a live grant stops being valid; <see cref="DateTimeOffset.MinValue"/> otherwise.</param>
/// <param name="Principal">The represented user as the application identified them; only for a live grant.</param>
public sealed record OnBehalfGrant(OnBehalfGrantStatus Status, DateTimeOffset ValidUntil, ClientPrincipal? Principal)
{
    /// <summary>
    /// Gets the answer for a grant the application says is not live.
    /// </summary>
    public static OnBehalfGrant NotLive { get; } = new(OnBehalfGrantStatus.NotLive, DateTimeOffset.MinValue, null);

    /// <summary>
    /// Gets the answer for a grant the application says expired.
    /// </summary>
    public static OnBehalfGrant Expired { get; } = new(OnBehalfGrantStatus.Expired, DateTimeOffset.MinValue, null);

    /// <summary>
    /// Gets the answer when no verdict could be obtained.
    /// </summary>
    public static OnBehalfGrant Indeterminate { get; } = new(OnBehalfGrantStatus.Indeterminate, DateTimeOffset.MinValue, null);

    /// <summary>
    /// Gets a value indicating whether the grant is live.
    /// </summary>
    public bool IsLive => Status == OnBehalfGrantStatus.Live && Principal is not null;

    /// <summary>
    /// Creates the answer for a live grant.
    /// </summary>
    /// <param name="validUntil">When the grant stops being valid.</param>
    /// <param name="principal">The represented user.</param>
    /// <returns>A live <see cref="OnBehalfGrant"/>.</returns>
    public static OnBehalfGrant Live(DateTimeOffset validUntil, ClientPrincipal principal) => new(OnBehalfGrantStatus.Live, validUntil, principal);
}
