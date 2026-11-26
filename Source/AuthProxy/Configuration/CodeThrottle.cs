// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Limits how often codes can be requested, counted before the application is called so the endpoint cannot be used to
/// send e-mail to arbitrary addresses.
/// </summary>
public class CodeThrottle
{
    /// <summary>
    /// Gets or sets the requests allowed per address within <see cref="Window"/>.
    /// </summary>
    public int PerAddress { get; set; } = 3;

    /// <summary>
    /// Gets or sets the requests allowed per client address within <see cref="Window"/>.
    /// </summary>
    public int PerClient { get; set; } = 10;

    /// <summary>
    /// Gets or sets the length of the counting window.
    /// </summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(10);
}
