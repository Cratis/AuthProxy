// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.given;

/// <summary>
/// A time provider that only moves when a specification moves it.
/// </summary>
public sealed class ManualTimeProvider : TimeProvider
{
    DateTimeOffset _now = new(2026, 11, 3, 9, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// Moves the clock forward.
    /// </summary>
    /// <param name="by">How far to move it.</param>
    public void Advance(TimeSpan by) => _now += by;

    /// <inheritdoc/>
    public override DateTimeOffset GetUtcNow() => _now;
}
