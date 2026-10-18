// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A signed forwarding deployment's key, and the settings that switch signing on with it.
/// </summary>
/// <remarks>
/// Each harness generates its own key when it starts, so no private key is checked in and a spec verifies with the
/// public half exactly as a backend that pinned it would.
/// </remarks>
public sealed class SignedForwarding
{
    /// <summary>The issuer every assertion carries.</summary>
    public const string Issuer = "authproxy-security-specs";

    /// <summary>The identifier of the signing key.</summary>
    public const string KeyId = "security-specs-2026";

    SignedForwarding(string privateKeyPem, string publicKeyPem)
    {
        PrivateKeyPem = privateKeyPem;
        PublicKeyPem = publicKeyPem;
    }

    /// <summary>Gets the EC P-256 private key AuthProxy signs with.</summary>
    public string PrivateKeyPem { get; }

    /// <summary>Gets the public key a backend verifies with.</summary>
    public string PublicKeyPem { get; }

    /// <summary>
    /// Generates a fresh key.
    /// </summary>
    /// <returns>The key.</returns>
    public static SignedForwarding Generate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new(key.ExportPkcs8PrivateKeyPem(), key.ExportSubjectPublicKeyInfoPem());
    }

    /// <summary>
    /// Adds the settings that switch signed forwarding on with this key.
    /// </summary>
    /// <param name="settings">The settings to add to.</param>
    public void AddTo(IDictionary<string, string?> settings)
    {
        const string section = $"{C.AuthProxy.SectionKey}:{nameof(C.AuthProxy.ForwardingAttestation)}";
        settings[$"{section}:Issuer"] = Issuer;
        settings[$"{section}:ActiveKeyId"] = KeyId;
        settings[$"{section}:SigningKeys:0:KeyId"] = KeyId;
        settings[$"{section}:SigningKeys:0:PrivateKeyPem"] = PrivateKeyPem;
    }
}
