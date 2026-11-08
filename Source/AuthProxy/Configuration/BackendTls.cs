// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Configures authenticated TLS for connections to backend hosts.
/// </summary>
public class BackendTls
{
    /// <summary>
    /// The default certificate polling interval.
    /// </summary>
    public static readonly TimeSpan DefaultReloadInterval = TimeSpan.FromMinutes(1);

    /// <summary>
    /// The minimum certificate polling interval.
    /// </summary>
    public static readonly TimeSpan MinimumReloadInterval = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Gets or sets whether every identity-bearing destination must use HTTPS, even without forwarded-identity signing.
    /// Defaults to false. LocalDevelopment permits HTTP only for loopback destinations.
    /// </summary>
    public bool RequireTlsOnIdentityHops { get; set; }

    /// <summary>
    /// Gets or sets the PEM client certificate and private key, or null to present no certificate.
    /// </summary>
    public BackendTlsClientCertificate? ClientCertificate { get; set; }

    /// <summary>
    /// Gets or sets the PEM trust bundle replacing system trust for backend hosts. Empty uses system trust.
    /// </summary>
    public string TrustedCertificateAuthoritiesPath { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets how often mounted certificate files are re-read.
    /// </summary>
    public TimeSpan ReloadInterval { get; set; } = DefaultReloadInterval;
}
