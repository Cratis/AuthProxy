// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cratis.AuthProxy.BackendHops;

/// <summary>
/// An immutable snapshot of validated backend TLS credentials and trust.
/// </summary>
/// <param name="ClientCertificate">The client leaf including its private key.</param>
/// <param name="TrustAnchors">The custom trust anchors, or an empty collection for system trust.</param>
/// <param name="Fingerprint">The SHA-256 digest of the loaded file bytes.</param>
internal sealed record BackendTlsMaterial(X509Certificate2? ClientCertificate, X509Certificate2Collection TrustAnchors, string Fingerprint)
{
    const string Prefix = "Cratis:AuthProxy:BackendTls:";

    /// <summary>
    /// Loads a coherent snapshot without exposing file content or exception messages on failure.
    /// </summary>
    /// <param name="settings">The mounted file settings.</param>
    /// <param name="now">The time used to validate the client certificate.</param>
    /// <param name="material">The validated snapshot.</param>
    /// <param name="problem">A fixed configuration-key diagnostic on failure.</param>
    /// <returns>Whether all configured material could be loaded.</returns>
    internal static bool TryLoad(Configuration.BackendTls settings, DateTimeOffset now, out BackendTlsMaterial? material, out string? problem)
    {
        material = null;
        problem = null;
        X509Certificate2? client = null;
        var anchors = new X509Certificate2Collection();
        var key = "ClientCertificate:CertificatePath";
        using var fingerprint = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        try
        {
            if (settings.ClientCertificate is { } paths)
            {
                if (string.IsNullOrWhiteSpace(paths.CertificatePath) || string.IsNullOrWhiteSpace(paths.KeyPath))
                {
                    problem = $"{Prefix}ClientCertificate:CertificatePath and {Prefix}ClientCertificate:KeyPath must both be set.";
                    return false;
                }

                var certificateBytes = File.ReadAllBytes(paths.CertificatePath);
                fingerprint.AppendData(certificateBytes);
                key = "ClientCertificate:KeyPath";
                var keyBytes = File.ReadAllBytes(paths.KeyPath);
                try
                {
                    fingerprint.AppendData(keyBytes);
                    using var loaded = X509Certificate2.CreateFromPem(System.Text.Encoding.UTF8.GetString(certificateBytes), System.Text.Encoding.UTF8.GetString(keyBytes));
                    client = X509CertificateLoader.LoadPkcs12(loaded.Export(X509ContentType.Pkcs12), null);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(keyBytes);
                }

                if (!client.HasPrivateKey || now.UtcDateTime < client.NotBefore.ToUniversalTime() || now.UtcDateTime > client.NotAfter.ToUniversalTime())
                {
                    problem = $"{Prefix}ClientCertificate:CertificatePath must contain a currently valid certificate with a private key.";
                    return false;
                }

                if (client.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(extension => !extension.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2")))
                {
                    problem = $"{Prefix}ClientCertificate:CertificatePath must permit client authentication.";
                    return false;
                }
            }

            key = "TrustedCertificateAuthoritiesPath";
            if (!string.IsNullOrEmpty(settings.TrustedCertificateAuthoritiesPath))
            {
                var bytes = File.ReadAllBytes(settings.TrustedCertificateAuthoritiesPath);
                fingerprint.AppendData(bytes);
                anchors.ImportFromPem(System.Text.Encoding.UTF8.GetString(bytes));
                if (anchors.Count == 0)
                {
                    problem = $"{Prefix}{key} must contain at least one PEM certificate.";
                    return false;
                }
            }

            material = new(client, anchors, Convert.ToHexString(fingerprint.GetHashAndReset()));
            return true;
        }
        catch (Exception exception) when (exception is CryptographicException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            // Invalid or inaccessible mounted files refuse the new snapshot; never disclose exception content.
            problem = $"{Prefix}{key} could not be loaded as valid PEM material.";
            return false;
        }
        finally
        {
            if (material is null)
            {
                client?.Dispose();
                foreach (var anchor in anchors) anchor.Dispose();
            }
        }
    }
}
