// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the root configuration for the auth proxy.
/// </summary>
public class AuthProxy
{
    /// <summary>
    /// The configuration section key for the root auth proxy settings.
    /// </summary>
    public const string SectionKey = "Cratis:AuthProxy";

    /// <summary>
    /// Gets or sets the authentication configuration.
    /// </summary>
    public Authentication Authentication { get; set; } = new();

    /// <summary>
    /// Gets or sets the invite system configuration.
    /// Set this section to enable invite-based onboarding.
    /// </summary>
    public Invite? Invite { get; set; }

    /// <summary>
    /// Gets or sets the tenant verification configuration.
    /// When set, the ingress calls the configured service to confirm that a resolved
    /// tenant exists before forwarding the request.
    /// Leave unset to skip tenant verification.
    /// </summary>
    public TenantVerification? TenantVerification { get; set; }

    /// <summary>
    /// Gets or sets the absolute path to a directory containing custom error pages.
    /// Pages are looked up by their <see cref="WellKnownPageNames"/> file name inside this directory.
    /// When empty or unset the ingress uses the built-in <c>Pages</c> directory.
    /// Override this by mounting a custom pages directory into the container and pointing
    /// this setting at the mount path.
    /// </summary>
    public string PagesPath { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the <see cref="Tenants"/>.
    /// Tenants are keyed by tenant ID string.
    /// </summary>
    public Tenants Tenants { get; set; } = new();

    /// <summary>
    /// Gets or sets the tenant resolution strategies applied in order until one resolves.
    /// </summary>
    public IList<TenantResolution> TenantResolutions { get; set; } = [];

    /// <summary>
    /// Gets or sets the services configuration.
    /// Services are keyed by a friendly name (e.g. "portal", "catalog").
    /// </summary>
    public IDictionary<string, Service> Services { get; set; } = new Dictionary<string, Service>();
}
