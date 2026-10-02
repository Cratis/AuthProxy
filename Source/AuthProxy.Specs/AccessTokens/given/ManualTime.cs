// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.given;

/// <summary>
/// A <see cref="TimeProvider"/> whose clock only moves when a spec moves it.
/// </summary>
/// <param name="now">The starting time.</param>
public class ManualTime(DateTimeOffset now) : TimeProvider
{
    DateTimeOffset _now = now;

    /// <inheritdoc/>
    public override DateTimeOffset GetUtcNow() => _now;

    /// <summary>
    /// Moves the clock forward.
    /// </summary>
    /// <param name="by">How far to move it.</param>
    public void Advance(TimeSpan by) => _now = _now.Add(by);
}
