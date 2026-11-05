// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cratis.AuthProxy.BackendHops.given;

public sealed class TestCertificates : IDisposable
{
    readonly string _directory = Path.Combine(Path.GetTempPath(), $"authproxy-hop-{Guid.NewGuid():N}");
    readonly RSA _authorityKey = RSA.Create(2048);

    public TestCertificates()
    {
        Directory.CreateDirectory(_directory);
        var request = new CertificateRequest("CN=Hop test CA", _authorityKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        Authority = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(30));
        File.WriteAllText(BundlePath, Authority.ExportCertificatePem());
        using var client = Issue(client: true);
        WriteClient(client);
    }

    public X509Certificate2 Authority { get; }
    public string CertificatePath => Path.Combine(_directory, "client.crt");
    public string KeyPath => Path.Combine(_directory, "client.key");
    public string BundlePath => Path.Combine(_directory, "ca.crt");
    public C.BackendTls Settings => new()
    {
        ClientCertificate = new() { CertificatePath = CertificatePath, KeyPath = KeyPath },
        TrustedCertificateAuthoritiesPath = BundlePath
    };

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
        using var leaf = request.Create(Authority, DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(expired ? -1 : 10), RandomNumberGenerator.GetBytes(16));
        using var withKey = leaf.CopyWithPrivateKey(key);
        return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);
    }

    public void WriteClient(X509Certificate2 certificate)
    {
        File.WriteAllText(CertificatePath, certificate.ExportCertificatePem());
        using var key = certificate.GetRSAPrivateKey()!;
        File.WriteAllText(KeyPath, key.ExportPkcs8PrivateKeyPem());
    }

    public void Dispose()
    {
        Authority.Dispose();
        _authorityKey.Dispose();
        Directory.Delete(_directory, recursive: true);
    }
}
