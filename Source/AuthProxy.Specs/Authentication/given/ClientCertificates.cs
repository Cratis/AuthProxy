// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cratis.AuthProxy.Authentication.given;

/// <summary>
/// Creates self-signed client certificates for client-assertion specs.
/// </summary>
public static class ClientCertificates
{
    /// <summary>
    /// Creates a self-signed RSA certificate with its private key.
    /// </summary>
    /// <param name="notBefore">The start of the validity period.</param>
    /// <param name="notAfter">The end of the validity period.</param>
    /// <returns>The certificate.</returns>
    public static X509Certificate2 Rsa(DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=authproxy-client", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(notBefore, notAfter);
    }

    /// <summary>
    /// Creates a self-signed RSA certificate valid around now.
    /// </summary>
    /// <returns>The certificate.</returns>
    public static X509Certificate2 Rsa() => Rsa(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
}
