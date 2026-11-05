// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cratis.AuthProxy.Security.given;

/// <summary>Ephemeral PEM credentials for real backend TLS handshakes.</summary>
public sealed class HopCertificates : IDisposable
{
    readonly string _directory = Path.Combine(Path.GetTempPath(), $"authproxy-hop-{Guid.NewGuid():N}");
    readonly RSA _authorityKey = RSA.Create(2048);
    readonly X509Certificate2 _authority;

    /// <summary>Creates an ephemeral CA and a client identity.</summary>
    public HopCertificates()
    {
        Directory.CreateDirectory(_directory);
        var request = new CertificateRequest("CN=Hop spec CA", _authorityKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        _authority = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(30));
        File.WriteAllText(BundlePath, _authority.ExportCertificatePem());
        RotateClient();
    }

    /// <summary>Gets the mounted client leaf path.</summary>
    public string CertificatePath => Path.Combine(_directory, "client.crt");

    /// <summary>Gets the mounted client key path.</summary>
    public string KeyPath => Path.Combine(_directory, "client.key");

    /// <summary>Gets the mounted CA bundle path.</summary>
    public string BundlePath => Path.Combine(_directory, "ca.crt");

    /// <summary>Gets the current client identity's SHA-256 fingerprint.</summary>
    public string ClientThumbprint { get; private set; } = string.Empty;

    /// <summary>Issues a leaf signed by this fixture's authority.</summary>
    /// <param name="client">Whether to permit client rather than server authentication.</param>
    /// <param name="expired">Whether the leaf has already expired.</param>
    /// <param name="host">The DNS subject alternative name.</param>
    /// <returns>The leaf including its private key.</returns>
    public X509Certificate2 Issue(bool client = false, bool expired = false, string host = "localhost")
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(client ? "1.3.6.1.5.5.7.3.2" : "1.3.6.1.5.5.7.3.1") }, true));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(host);
        request.CertificateExtensions.Add(san.Build());
        using var leaf = request.Create(_authority, DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(expired ? -1 : 10), RandomNumberGenerator.GetBytes(16));
        using var withKey = leaf.CopyWithPrivateKey(key);
        return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);
    }

    /// <summary>Replaces both mounted client files without restarting the proxy.</summary>
    public void RotateClient()
    {
        using var client = Issue(client: true);
        File.WriteAllText(CertificatePath, client.ExportCertificatePem());
        using var key = client.GetRSAPrivateKey()!;
        File.WriteAllText(KeyPath, key.ExportPkcs8PrivateKeyPem());
        ClientThumbprint = client.GetCertHashString(HashAlgorithmName.SHA256);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _authority.Dispose();
        _authorityKey.Dispose();
        Directory.Delete(_directory, recursive: true);
    }
}
