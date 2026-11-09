// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// A clock a spec moves by hand.
/// </summary>
public sealed class ManualTimeProvider : TimeProvider
{
    DateTimeOffset _now = new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <inheritdoc/>
    public override DateTimeOffset GetUtcNow() => _now;

    /// <summary>
    /// Moves the clock forward.
    /// </summary>
    /// <param name="by">How far.</param>
    public void Advance(TimeSpan by) => _now += by;
}
