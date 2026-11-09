// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_validating_v2_configuration : Specification
{
    [Fact]
    public void should_accept_only_pinned_p256_private_material()
    {
        var settings = when_signing_with_explicit_trusted_context.Settings();
        Assert.True(ForwardedIdentitySigningKey.TryCreate(settings, out var key, out _));
        Assert.Equal("v2", key!.Version);
        settings.SecretBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        Assert.False(ForwardedIdentitySigningKey.TryCreate(settings, out _, out _));
    }

    [Theory]
    [InlineData("v1")]
    [InlineData("V2")]
    [InlineData("v3")]
    public void should_reject_unsupported_versions_or_mixed_material(string version)
    {
        var settings = when_signing_with_explicit_trusted_context.Settings();
        settings.Version = version;
        Assert.False(ForwardedIdentitySigningKey.TryCreate(settings, out _, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("UPPER")]
    [InlineData("https://api.example.test")]
    [InlineData("two--parts")]
    [InlineData("trailing-")]
    public void should_reject_non_slug_audiences(string audience)
    {
        var settings = when_signing_with_explicit_trusted_context.Settings();
        settings.Audience = audience;
        Assert.False(ForwardedIdentitySigningKey.TryCreate(settings, out _, out _));
    }

    [Fact]
    public void should_reject_public_keys_other_curves_trailing_bytes_and_invalid_base64()
    {
        var settings = when_signing_with_explicit_trusted_context.Settings();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        foreach (var material in new[] { key.ExportPkcs8PrivateKey(), key.ExportSubjectPublicKeyInfo(), Convert.FromBase64String(settings.PrivateKeyPkcs8Base64).Concat(new byte[] { 0 }).ToArray() })
        {
            settings.PrivateKeyPkcs8Base64 = Convert.ToBase64String(material);
            Assert.False(ForwardedIdentitySigningKey.TryCreate(settings, out _, out _));
        }
        settings.PrivateKeyPkcs8Base64 = "not-base64";
        Assert.False(ForwardedIdentitySigningKey.TryCreate(settings, out _, out var problem));
        Assert.DoesNotContain(settings.PrivateKeyPkcs8Base64, problem, StringComparison.Ordinal);
    }

    [Fact]
    public void should_reject_cross_application_reuse_through_the_startup_validator()
    {
        var settings = when_signing_with_explicit_trusted_context.Settings();
        var config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["first"] = new() { Backend = new() { BaseUrl = "https://first.example/" }, ForwardedIdentity = settings },
                ["second"] = new() { Backend = new() { BaseUrl = "https://second.example/" }, ForwardedIdentity = settings }
            }
        };
        Assert.True(new ForwardedIdentitySigningConfigurationValidator().Validate(null, config).Failed);
    }
}
