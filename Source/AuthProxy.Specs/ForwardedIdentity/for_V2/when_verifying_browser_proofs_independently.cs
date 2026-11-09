// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Cratis.AuthProxy.OnBehalfSessions;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging.Abstractions;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public partial class when_verifying_browser_proofs_independently : Specification
{
    static readonly Dictionary<string, Action<HttpRequestMessage>> _attacks = new(StringComparer.Ordinal)
    {
        ["tenant"] = request => Replace(request, "x-workforce-tenant", "other"),
        ["principal"] = request => Replace(request, "x-ms-client-principal-id", "other"),
        ["credential"] = request => Replace(request, "x-cratis-credential-id", Guid.NewGuid().ToString("D")),
        ["time"] = request => Replace(request, "x-cratis-auth-time", "1700000001"),
        ["actor"] = request => request.Headers.Add("x-cratis-act", "e30"),
        ["path"] = request => request.RequestUri = new("https://backend.example/changed"),
        ["method"] = request => request.Method = HttpMethod.Post,
        ["duplicate"] = request => request.Headers.TryAddWithoutValidation("x-workforce-tenant", "second"),
        ["signature"] = request => Replace(request, "x-cratis-forwarded-identity-signature", "v1.old-proof"),
        ["removed"] = request => request.Headers.Remove("x-ms-client-principal-id"),
        ["audience"] = _ => { }
    };

    static BrowserVerifier Verifier(BrowserSessionFixture fixture, Action<ReceiverConfiguration>? configure = null)
    {
        using var key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(Convert.FromBase64String(fixture.Settings.PrivateKeyPkcs8Base64), out _);
        var config = new ReceiverConfiguration
        {
            PublicKey = key.ExportSubjectPublicKeyInfo(),
            Audience = fixture.Settings.Audience,
            KeyId = fixture.Settings.KeyId,
            TenantHeader = fixture.Settings.TenantHeader
        };
        configure?.Invoke(config);
        return new(config);
    }

    static void Replace(HttpRequestMessage request, string name, string value)
    {
        request.Headers.Remove(name);
        request.Headers.Add(name, value);
    }

    [Fact]
    public void should_accept_a_real_session_proof_using_only_the_receivers_public_key_and_configuration()
    {
        using var fixture = new BrowserSessionFixture();
        using var request = fixture.Request();
        Assert.Equal(ForwardedIdentitySigningOutcome.SignatureCreated, fixture.Signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        var verifier = Verifier(fixture);
        Assert.True(verifier.Accept(request));
        Assert.False(verifier.Accept(request));
    }

    [Theory]
    [InlineData("tenant")]
    [InlineData("principal")]
    [InlineData("credential")]
    [InlineData("time")]
    [InlineData("actor")]
    [InlineData("path")]
    [InlineData("method")]
    [InlineData("audience")]
    [InlineData("duplicate")]
    [InlineData("signature")]
    [InlineData("removed")]
    public void should_reject_hostile_changes_without_using_the_producers_canonicalizer(string attack)
    {
        using var fixture = new BrowserSessionFixture();
        using var request = fixture.Request();
        Assert.Equal(ForwardedIdentitySigningOutcome.SignatureCreated, fixture.Signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        _attacks[attack](request);
        Assert.False(Verifier(fixture, config => config.Audience = attack == "audience" ? "other-app" : fixture.Settings.Audience).Accept(request));
    }

    [Theory]
    [InlineData(-120)]
    [InlineData(120)]
    public void should_reject_correctly_signed_stale_and_future_proofs(int offsetSeconds)
    {
        using var fixture = new BrowserSessionFixture();
        using var request = fixture.Request();
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["app"] = new() { ForwardedIdentity = fixture.Settings } } });
        var issued = DateTimeOffset.UtcNow.AddSeconds(offsetSeconds);
        using var signer = new ForwardedIdentitySigner(monitor, new FixedTime(issued), NullLogger<ForwardedIdentitySigner>.Instance, fixture.Accessor);
        Assert.Equal(ForwardedIdentitySigningOutcome.SignatureCreated, signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        Assert.True(Verifier(fixture, config => config.Now = issued).Accept(request));
        Assert.False(Verifier(fixture).Accept(request));
    }

    [Fact]
    public void should_reject_a_wrong_key_identifier_and_a_foreign_public_key()
    {
        using var fixture = new BrowserSessionFixture();
        using var request = fixture.Request();
        Assert.Equal(ForwardedIdentitySigningOutcome.SignatureCreated, fixture.Signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        Assert.True(Verifier(fixture).Accept(request));
        Assert.False(Verifier(fixture, config => config.KeyId = "another-key").Accept(request));
        using var foreign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = Verifier(fixture, config => config.PublicKey = foreign.ExportSubjectPublicKeyInfo());
        Assert.False(verifier.Accept(request));
    }

    [Fact]
    public void should_refuse_an_on_behalf_request_even_with_a_valid_browser_cookie()
    {
        using var fixture = new BrowserSessionFixture();
        using var request = fixture.Request();
        fixture.Context.SetOnBehalf(new(null!, new ClientPrincipal(), "actor", Substitute.For<IOnBehalfAttestations>()));
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, fixture.Signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        Assert.False(Verifier(fixture).Accept(request));
    }

    [Fact]
    public async Task should_strip_attacker_ingress_headers_before_issuing_an_independently_verifiable_proof()
    {
        using var fixture = new BrowserSessionFixture();
        var config = new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["app"] = new() { ForwardedIdentity = fixture.Settings } } };
        fixture.Context.Request.Headers[Headers.PrincipalId] = "attacker";
        fixture.Context.Request.Headers[Headers.ForwardedIdentitySignature] = "v2.attacker";
        fixture.Context.Request.Headers["x-cratis-subject"] = "attacker";
        fixture.Context.Request.Headers["x-workforce-tenant"] = "attacker";
        fixture.Context.Request.Headers["x_workforce_tenant"] = "attacker";
        var ingress = new ApplicationBuilder(fixture.Context.RequestServices);
        ingress.Use(async (context, next) =>
        {
            // The ingress boundary, followed by the gateway's trusted identity projection and signing.
            SpoofableHeaders.Strip(context.Request.Headers);
            ForwardedIdentityTenantHeader.Strip(context.Request.Headers, config);
            await next(context);
        });
        ingress.Run(context =>
        {
            Assert.False(context.Request.Headers.ContainsKey(Headers.PrincipalId));
            Assert.False(context.Request.Headers.ContainsKey(Headers.ForwardedIdentitySignature));
            Assert.False(context.Request.Headers.ContainsKey("x-cratis-subject"));
            Assert.False(context.Request.Headers.ContainsKey("x-workforce-tenant"));
            Assert.False(context.Request.Headers.ContainsKey("x_workforce_tenant"));
            using var request = fixture.Request();
            foreach (var header in context.Request.Headers) request.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            Assert.Equal(ForwardedIdentitySigningOutcome.SignatureCreated, fixture.Signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
            Assert.True(Verifier(fixture).Accept(request));
            return Task.CompletedTask;
        });
        await ingress.Build()(fixture.Context);
    }

    sealed class ReceiverConfiguration
    {
        internal required byte[] PublicKey { get; set; }
        internal required string Audience { get; set; }
        internal required string KeyId { get; set; }
        internal required string TenantHeader { get; init; }
        internal DateTimeOffset? Now { get; set; }
    }

    sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    /// <summary>
    /// Independent, browser-only test receiver from the Arc v2 spec: no production canonicalizer, context
    /// projector, envelope parser, principal parser or private key is used below this boundary.
    /// </summary>
    /// <param name="config">The receiver's verification key, expected identifiers and clock.</param>
    private sealed partial class BrowserVerifier(ReceiverConfiguration config)
    {
        static readonly string[] _context = ["x-cratis-credential-kind", "x-cratis-credential-id", "x-cratis-issuer", "x-cratis-subject", "x-cratis-idp", "x-cratis-auth-time", "x-cratis-acr", "x-cratis-amr", "x-cratis-act", "x-cratis-grant-id", "x-cratis-policy-epoch", "x-cratis-sender-binding", "x-cratis-bearer-sha256"];
        static readonly string[] _routing = ["x-cratis-token-client-id", "x-cratis-token-scope", "x-cratis-tenant-id", "tenant-id", "x-cratis-microservice", "service-id"];
        static readonly string[] _unsupported = ["x-cratis-act", "x-cratis-grant-id", "x-cratis-bearer-sha256"];
        readonly HashSet<string> _nonces = new(StringComparer.Ordinal);

        [GeneratedRegex("^(?:0|[1-9][0-9]{0,18})$", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, 1000)]
        private static partial Regex TimestampFormat { get; }

        [GeneratedRegex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, 1000)]
        private static partial Regex AccountFormat { get; }

        [GeneratedRegex("%[0-9a-fA-F]{2}", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, 1000)]
        private static partial Regex PercentFormat { get; }

        static bool IsBrowser(SortedDictionary<string, string> snapshot)
        {
            if (snapshot["x-cratis-credential-kind"] != "browser-session" || snapshot["x-cratis-sender-binding"] != "none") return false;
            if (!Guid.TryParseExact(snapshot["x-cratis-credential-id"], "D", out var credential) || credential == Guid.Empty) return false;
            return !snapshot.Keys.Any(IsUnsupported);
        }

        static bool IsUnsupported(string name) => name.StartsWith("x-cratis-on-behalf", StringComparison.Ordinal)
            || _unsupported.Contains(name);

        static bool IsPerson(SortedDictionary<string, string> snapshot)
        {
            if (snapshot["x-cratis-issuer"] != BrowserSessionFixture.Realm || snapshot["x-cratis-idp"] != "https://upstream.example/") return false;
            if (snapshot["x-cratis-auth-time"] != "1700000000" || snapshot["x-cratis-acr"] != "basic") return false;
            return AccountFormat.IsMatch(snapshot["x-cratis-subject"]);
        }

        static bool IsPrincipal(SortedDictionary<string, string> snapshot)
        {
            using var principal = JsonDocument.Parse(Convert.FromBase64String(snapshot["x-ms-client-principal"]));
            if (principal.RootElement.GetProperty("userId").GetString() != snapshot["x-cratis-subject"]) return false;
            return snapshot["x-ms-client-principal-id"] == snapshot["x-cratis-subject"] && snapshot["x-ms-client-principal-name"].Length != 0;
        }

        static void Add(SortedDictionary<string, string> snapshot, string name, IEnumerable<string> values)
        {
            var entries = values.ToArray();
            if (entries.Length != 1 || !snapshot.TryAdd(name, entries[0].Trim(' ', '\t'))) throw new FormatException();
            if (snapshot.Count > 64) throw new FormatException();
            if (snapshot[name].Any(character => character < 32 || character > 126)) throw new FormatException();
        }

        static void Frame(StringBuilder builder, string value) => builder.Append(Encoding.UTF8.GetByteCount(value).ToString(CultureInfo.InvariantCulture)).Append(':').Append(value).Append('\n');

        static byte[] Decode(string text)
        {
            if (text.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_')) throw new FormatException();
            var bytes = Convert.FromBase64String(text.Replace('-', '+').Replace('_', '/') + new string('=', (4 - (text.Length % 4)) % 4));
            if (Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') != text) throw new FormatException();
            return bytes;
        }

        internal bool Accept(HttpRequestMessage request)
        {
            try
            {
                var parts = Envelope(request);
                if (parts is null) return false;
                var snapshot = Snapshot(request);
                if (!IsBrowser(snapshot)) return false;
                if (!IsPerson(snapshot)) return false;
                if (!IsPrincipal(snapshot)) return false;
                var input = Canonical(request, parts, snapshot);
                if (input.Length > 32768) return false;
                using var verifier = ECDsa.Create();
                verifier.ImportSubjectPublicKeyInfo(config.PublicKey, out _);
                return verifier.VerifyData(input, Decode(parts[4]), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation) && _nonces.Add(parts[3]);
            }
            catch (Exception error) when (error is ArgumentException or FormatException or InvalidOperationException or KeyNotFoundException or JsonException or CryptographicException or OverflowException)
            {
                return false;
            }
        }

        string[]? Envelope(HttpRequestMessage request)
        {
            var envelope = request.Headers.GetValues("x-cratis-forwarded-identity-signature").Single();
            var parts = envelope.Split('.');
            if (envelope.Length > 256 || parts.Length != 5) return null;
            if (parts[0] != "v2" || parts[1] != config.KeyId) return null;
            if (!IsFresh(parts[2])) return null;
            if (Decode(parts[3]).Length != 16) return null;
            return Decode(parts[4]).Length == 64 ? parts : null;
        }

        bool IsFresh(string text)
        {
            if (!TimestampFormat.IsMatch(text)) return false;
            var timestamp = long.Parse(text, CultureInfo.InvariantCulture);
            var now = (config.Now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
            return timestamp >= now - 60 && timestamp <= now + 30;
        }

        SortedDictionary<string, string> Snapshot(HttpRequestMessage request)
        {
            var snapshot = new SortedDictionary<string, string>(StringComparer.Ordinal);
            var headers = request.Headers.NonValidated.Select(header => KeyValuePair.Create(header.Key, header.Value.AsEnumerable()));
            if (request.Content is not null) headers = headers.Concat(request.Content.Headers.NonValidated.Select(header => KeyValuePair.Create(header.Key, header.Value.AsEnumerable())));
            foreach (var header in headers)
            {
                var name = header.Key.ToLowerInvariant();
                if (IsCovered(name)) Add(snapshot, name, header.Value);
            }
            return snapshot;
        }

        bool IsCovered(string name) => name.StartsWith("x-ms-client-principal", StringComparison.Ordinal)
            || name.StartsWith("x-cratis-on-behalf", StringComparison.Ordinal) || _context.Contains(name)
            || _routing.Contains(name) || name.Equals(config.TenantHeader, StringComparison.OrdinalIgnoreCase);

        byte[] Canonical(HttpRequestMessage request, string[] parts, SortedDictionary<string, string> snapshot)
        {
            var path = PercentFormat.Replace(request.RequestUri!.AbsolutePath, match => match.Value.ToUpperInvariant());
            var canonical = new StringBuilder("Cratis.AuthProxy.ForwardedIdentity.v2\n");
            foreach (var value in new[] { config.Audience, config.KeyId, parts[2], parts[3], request.Method.Method, path, snapshot.Count.ToString(CultureInfo.InvariantCulture) }) Frame(canonical, value);
            foreach (var header in snapshot)
            {
                Frame(canonical, header.Key);
                Frame(canonical, header.Value);
            }
            return Encoding.UTF8.GetBytes(canonical.ToString());
        }
    }
}
