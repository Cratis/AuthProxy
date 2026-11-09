// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_caching_v2_signing_keys : Specification
{
    [Fact]
    public void should_reuse_one_handle_per_key_and_retire_handles_on_reload_and_disposal()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        Action<C.AuthProxy, string?>? reload = null;
        monitor.OnChange(Arg.Do<Action<C.AuthProxy, string?>>(callback => reload = callback)).Returns(Substitute.For<IDisposable>());
        using var cache = new ForwardedIdentityV2SigningKeyCache(monitor);
        var settings = when_signing_with_explicit_trusted_context.Settings();
        Assert.True(Sign(cache, settings));
        Assert.True(Sign(cache, settings));
        Assert.Equal(1, cache.Count);
        settings.PrivateKeyPkcs8Base64 = when_signing_with_explicit_trusted_context.Settings().PrivateKeyPkcs8Base64;
        Assert.True(Sign(cache, settings));
        Assert.Equal(2, cache.Count);
        reload!(new(), null);
        Assert.Equal(0, cache.Count);
        Assert.True(Sign(cache, settings));
        Assert.Equal(1, cache.Count);
        cache.Dispose();
        Assert.Equal(0, cache.Count);
        Assert.Throws<ObjectDisposedException>(() => Sign(cache, settings));
    }

    [Fact]
    public void should_recheck_key_selection_even_for_cached_material()
    {
        using var cache = new ForwardedIdentityV2SigningKeyCache(Substitute.For<IOptionsMonitor<C.AuthProxy>>());
        var settings = when_signing_with_explicit_trusted_context.Settings();
        Assert.True(Sign(cache, settings));
        settings.Version = "v1";
        Assert.False(Sign(cache, settings));
        settings.Version = "v2";
        settings.SecretBase64 = "mixed-material";
        Assert.False(Sign(cache, settings));
    }

    [Fact]
    public void should_retain_only_a_public_fingerprint_after_configuration_validation()
    {
        var settings = when_signing_with_explicit_trusted_context.Settings();
        Assert.True(ForwardedIdentitySigningKey.TryCreate(settings, out var key, out _));
        using var signer = ECDsa.Create();
        signer.ImportPkcs8PrivateKey(Convert.FromBase64String(settings.PrivateKeyPkcs8Base64), out _);
        Assert.Equal(SHA256.HashData(signer.ExportSubjectPublicKeyInfo()), key!.Secret.ToArray());
    }

    [Theory]
    [InlineData("nistP256")]
    [InlineData("ECDSA_P256")]
    [InlineData("prime256v1")]
    [InlineData("secp256r1")]
    public void should_accept_platform_friendly_names_without_an_oid_value(string name)
    {
        var curve = new Oid(null, name);
        Assert.Null(curve.Value);
        Assert.True(ForwardedIdentityV2SigningKey.IsP256(curve));
    }

    [Fact]
    public void should_not_allow_a_friendly_name_to_override_a_different_curve_oid()
    {
        Assert.False(ForwardedIdentityV2SigningKey.IsP256(new Oid("1.3.132.0.34", "nistP256")));
        Assert.False(ForwardedIdentityV2SigningKey.IsP256(new Oid(null, "nistP384")));
    }

    static bool Sign(ForwardedIdentityV2SigningKeyCache cache, C.ForwardedIdentitySigning settings) => cache.TrySign(settings, "1700000000", "AAECAwQFBgcICQoLDA0ODw", [1, 2, 3], out _);
}
