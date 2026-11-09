// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_signing_with_explicit_trusted_context : Specification
{
    [Fact]
    public void should_refuse_without_context_even_when_identity_headers_are_present()
    {
        using var fixture = V2Vector.Load();
        var input = fixture.RootElement.GetProperty("cases")[0].GetProperty("inputs");
        using var request = V2Vector.Request(input);
        request.Headers.Add(Headers.ForwardedIdentitySignature, "v1.caller-proof");
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, Signer(Settings()).Sign(request, Target()));
        Assert.False(request.Headers.Contains(Headers.ForwardedIdentitySignature));
    }

    [Fact]
    public void should_refuse_anonymous_requests_without_context_instead_of_bypassing_signing()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.example/");
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, Signer(Settings()).Sign(request, Target()));
    }

    [Fact]
    public void should_create_a_fresh_es256_envelope_on_each_hop_and_replace_untrusted_context_headers()
    {
        using var fixture = V2Vector.Load();
        var input = fixture.RootElement.GetProperty("cases")[0].GetProperty("inputs");
        using var request = V2Vector.Request(input);
        var context = V2Vector.Context(input) with { CredentialKind = "browser-session", SenderBinding = "none", Actor = null, GrantId = null };
        request.Headers.Remove("x-cratis-on-behalf-context");
        request.Options.Set(ForwardedIdentityTrustedContext.OptionsKey, context);
        request.Headers.Remove("x-cratis-credential-id");
        request.Headers.Add("x-cratis-credential-id", "caller-controlled");
        var settings = Settings();
        settings.TenantHeader = context.TenantHeader;
        var signer = Signer(settings);
        Assert.Equal(ForwardedIdentitySigningOutcome.SignatureCreated, signer.Sign(request, Target()));
        var first = request.Headers.GetValues(Headers.ForwardedIdentitySignature).Single();
        Assert.StartsWith("v2.key-1.", first, StringComparison.Ordinal);
        Assert.Equal(context.CredentialId, request.Headers.GetValues("x-cratis-credential-id").Single());
        Assert.Equal(ForwardedIdentitySigningOutcome.SignatureCreated, signer.Sign(request, Target()));
        var second = request.Headers.GetValues(Headers.ForwardedIdentitySignature).Single();
        Assert.NotEqual(first.Split('.')[3], second.Split('.')[3]);
        var parts = second.Split('.');
        Assert.True(ForwardedIdentityV2CanonicalInput.TryCreate(request, context, settings.Audience, settings.KeyId, parts[2], parts[3], out var canonical));
        using var verifier = ECDsa.Create();
        verifier.ImportPkcs8PrivateKey(Convert.FromBase64String(settings.PrivateKeyPkcs8Base64), out _);
        Assert.True(verifier.VerifyData(canonical, Convert.FromBase64String(parts[4].Replace('-', '+').Replace('_', '/') + "=="), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    [Fact]
    public void should_not_sign_after_trusted_authentication_evidence_is_removed()
    {
        using var fixture = V2Vector.Load();
        var input = fixture.RootElement.GetProperty("cases")[0].GetProperty("inputs");
        using var request = V2Vector.Request(input);
        request.Options.Set(ForwardedIdentityTrustedContext.OptionsKey, V2Vector.Context(input) with { Person = null });
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, Signer(Settings()).Sign(request, Target()));
        Assert.False(request.Headers.Contains(Headers.ForwardedIdentitySignature));
    }

    [Fact]
    public void should_keep_private_material_out_of_diagnostics()
    {
        var settings = Settings();
        Assert.True(ForwardedIdentitySigningKey.TryCreate(settings, out var key, out _));
        Assert.DoesNotContain(settings.PrivateKeyPkcs8Base64, settings.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(settings.PrivateKeyPkcs8Base64, key!.ToString(), StringComparison.Ordinal);
        var context = new ForwardedIdentityTrustedContext("pat", "not-for-logs", "none") { Bearer = new("not-for-logs", "pat-verifier", "issuer", "subject") };
        Assert.DoesNotContain("not-for-logs", context.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("not-for-logs", context.Bearer.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void should_not_log_private_key_material_on_refusal()
    {
        var settings = Settings();
        var logger = Substitute.For<ILogger<ForwardedIdentitySigner>>();
        logger.IsEnabled(Arg.Any<LogLevel>()).Returns(true);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.example/");
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, Signer(settings, logger).Sign(request, Target()));
        var messages = logger.ReceivedCalls().Where(call => call.GetMethodInfo().Name == "Log").Select(call => call.GetArguments()[2]!.ToString()!).ToArray();
        Assert.NotEmpty(messages);
        Assert.All(messages, message => Assert.False(message.Contains(settings.PrivateKeyPkcs8Base64, StringComparison.Ordinal)));
    }

    internal static C.ForwardedIdentitySigning Settings()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new() { Version = "v2", Audience = "backend", KeyId = "key-1", PrivateKeyPkcs8Base64 = Convert.ToBase64String(key.ExportPkcs8PrivateKey()) };
    }

    internal static ForwardedIdentitySigner Signer(C.ForwardedIdentitySigning settings, ILogger<ForwardedIdentitySigner>? logger = null)
    {
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["app"] = new() { ForwardedIdentity = settings } } });
        return new(monitor, TimeProvider.System, logger ?? NullLogger<ForwardedIdentitySigner>.Instance);
    }

    internal static ForwardedIdentitySigningTarget Target() => new(ForwardedIdentityFlow.ProxiedRequest, "app");
}
