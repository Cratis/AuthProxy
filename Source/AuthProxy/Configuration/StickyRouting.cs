// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the opt-in setting that pins each browser to one replica of a service's backend.
/// </summary>
/// <remarks>
/// The replicas are discovered through DNS, so they must be individually reachable, for example behind a
/// Kubernetes headless Service. Stickiness is a performance hint for per-replica caches. It is never a security
/// boundary: a backend must still scope what it serves by user and tenant.
/// </remarks>
public class StickyRouting
{
    /// <summary>
    /// The default for <see cref="RefreshInterval"/>.
    /// </summary>
    public static readonly TimeSpan DefaultRefreshInterval = TimeSpan.FromSeconds(15);

    /// <summary>
    /// The shortest accepted <see cref="RefreshInterval"/>.
    /// </summary>
    internal static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromSeconds(1);

    /// <summary>
    /// The longest accepted <see cref="RefreshInterval"/>.
    /// </summary>
    internal static readonly TimeSpan MaximumRefreshInterval = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets or sets a value indicating whether sticky routing is on. It is off by default.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Gets or sets the DNS host name that resolves to the replicas. Leave empty to use the host of the
    /// endpoint's <see cref="ServiceEndpoint.BaseUrl"/>.
    /// </summary>
    public string ReplicaHost { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets how often the replicas are discovered again. Must be between one second and one hour.
    /// </summary>
    public TimeSpan RefreshInterval { get; set; } = DefaultRefreshInterval;
}
