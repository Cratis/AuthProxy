// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BackendHops;

/// <summary>
/// Applies backend-only client authentication and custom trust while preserving hostname validation.
/// </summary>
/// <param name="config">The backend host configuration.</param>
/// <param name="material">The live material snapshots.</param>
/// <param name="logger">The redacted handshake diagnostic logger.</param>
internal sealed class BackendTlsHttpClientPolicy(IOptionsMonitor<C.AuthProxy> config, IBackendTlsMaterialSource material, ILogger<BackendTlsHttpClientPolicy> logger)
{
    /// <summary>
    /// Creates a redirect-disabled, cookie-free back-channel handler with the shared TLS policy.
    /// </summary>
    /// <returns>The configured transport.</returns>
    internal SocketsHttpHandler CreateHandler()
    {
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false };
        Apply(handler);
        return handler;
    }

    /// <summary>
    /// Configures a handler without changing its HTTP or YARP transport settings.
    /// </summary>
    /// <param name="handler">The transport handler.</param>
    internal void Apply(SocketsHttpHandler handler)
    {
        // Force initial validation now, rather than discovering invalid files in a handshake callback.
        var current = material.Current;
        if (current.ClientCertificate is not null || current.TrustAnchors.Count > 0)
        {
            handler.PooledConnectionLifetime = config.CurrentValue.BackendTls.ReloadInterval;
        }
        handler.SslOptions.LocalCertificateSelectionCallback = (_, host, _, _, _) => SelectClientCertificate(host);
        handler.SslOptions.RemoteCertificateValidationCallback = (sender, certificate, chain, errors) =>
            ValidateServerCertificate((sender as SslStream)?.TargetHostName ?? string.Empty, certificate, chain, errors);
    }

    /// <summary>
    /// Selects the latest client certificate only for explicitly configured backend hosts.
    /// </summary>
    /// <param name="host">The TLS target host.</param>
    /// <returns>The client certificate, or null for other hosts.</returns>
    internal X509Certificate2? SelectClientCertificate(string host) =>
        IsBackend(host) ? material.Current.ClientCertificate : null;

    /// <summary>
    /// Validates the peer, retaining platform hostname and missing-certificate checks.
    /// </summary>
    /// <param name="host">The TLS target host.</param>
    /// <param name="certificate">The peer certificate.</param>
    /// <param name="peerChain">The peer chain, including any presented intermediates.</param>
    /// <param name="errors">The platform validation result.</param>
    /// <returns>Whether the backend peer is authenticated.</returns>
    internal bool ValidateServerCertificate(string host, X509Certificate? certificate, X509Chain? peerChain, SslPolicyErrors errors)
    {
        if (certificate is null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != SslPolicyErrors.None) return Refuse(host, "missing certificate or hostname mismatch");
        if (!IsBackend(host)) return errors == SslPolicyErrors.None || Refuse(host, "system trust validation failed");
        var current = material.Current;
        if (current.TrustAnchors.Count == 0) return errors == SslPolicyErrors.None || Refuse(host, "system trust validation failed");
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(current.TrustAnchors);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.ApplicationPolicy.Add(new("1.3.6.1.5.5.7.3.1"));
        if (peerChain is not null)
        {
            foreach (var element in peerChain.ChainElements.Cast<X509ChainElement>().Skip(1)) chain.ChainPolicy.ExtraStore.Add(element.Certificate);
        }
        using var leaf = new X509Certificate2(certificate);
        return chain.Build(leaf) || Refuse(host, "custom trust chain, validity or server authentication failed");
    }

    bool Refuse(string host, string reason)
    {
        logger.HandshakeRefused(host, reason);
        return false;
    }

    bool IsBackend(string host) => BackendHopHosts.For(config.CurrentValue).Contains(host);
}
