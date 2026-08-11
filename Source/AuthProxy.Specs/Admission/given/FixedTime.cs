// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.given;

/// <summary>
/// A clock a spec moves by hand, so an expiry can be reached without waiting for one.
/// </summary>
/// <param name="now">The time it starts at.</param>
public sealed class FixedTime(DateTimeOffset now) : TimeProvider
{
    /// <summary>
    /// Gets or sets what the clock currently reads.
    /// </summary>
    public DateTimeOffset Now { get; set; } = now;

    /// <inheritdoc/>
    public override DateTimeOffset GetUtcNow() => Now;
}
