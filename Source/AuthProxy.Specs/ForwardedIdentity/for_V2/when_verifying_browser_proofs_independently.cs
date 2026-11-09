// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public partial class when_verifying_browser_proofs_independently : Specification
{
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
    public void should_reject_hostile_changes_without_using_the_producers_canonicalizer(string attack)
    {
        using var fixture = new BrowserSessionFixture();
        using var request = fixture.Request();
        Assert.Equal(ForwardedIdentitySigningOutcome.SignatureCreated, fixture.Signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        switch (attack)
        {
            case "tenant": Replace(request, "x-workforce-tenant", "other"); break;
            case "principal": Replace(request, "x-ms-client-principal-id", "other"); break;
            case "credential": Replace(request, "x-cratis-credential-id", Guid.NewGuid().ToString("D")); break;
            case "time": Replace(request, "x-cratis-auth-time", "1700000001"); break;
            case "actor": request.Headers.Add("x-cratis-act", "e30"); break;
            case "path": request.RequestUri = new("https://backend.example/changed"); break;
            case "method": request.Method = HttpMethod.Post; break;
            case "duplicate": request.Headers.TryAddWithoutValidation("x-workforce-tenant", "second"); break;
            case "signature": Replace(request, "x-cratis-forwarded-identity-signature", "v1.old-proof"); break;
        }
        Assert.False(Verifier(fixture, attack == "audience" ? "other-app" : fixture.Settings.Audience).Accept(request));
    }

    static BrowserVerifier Verifier(BrowserSessionFixture fixture, string? audience = null)
    {
        using var key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(Convert.FromBase64String(fixture.Settings.PrivateKeyPkcs8Base64), out _);
        return new(key.ExportSubjectPublicKeyInfo(), audience ?? fixture.Settings.Audience, fixture.Settings.KeyId, fixture.Settings.TenantHeader);
    }

    static void Replace(HttpRequestMessage request, string name, string value)
    {
        request.Headers.Remove(name);
        request.Headers.Add(name, value);
    }

    /// <summary>
    /// Independent, browser-only test receiver from the Arc v2 spec: no production canonicalizer, context
    /// projector, envelope parser, principal parser or private key is used below this boundary.
    /// </summary>
    /// <param name="publicKey">The receiver's public verification key.</param>
    /// <param name="audience">The receiver-configured audience.</param>
    /// <param name="keyId">The receiver-configured key identifier.</param>
    /// <param name="tenantHeader">The receiver-configured tenant header.</param>
    private sealed partial class BrowserVerifier(byte[] publicKey, string audience, string keyId, string tenantHeader)
    {
        static readonly string[] _context = ["x-cratis-credential-kind", "x-cratis-credential-id", "x-cratis-issuer", "x-cratis-subject", "x-cratis-idp", "x-cratis-auth-time", "x-cratis-acr", "x-cratis-amr", "x-cratis-act", "x-cratis-grant-id", "x-cratis-policy-epoch", "x-cratis-sender-binding", "x-cratis-bearer-sha256"];
        static readonly string[] _routing = ["x-cratis-token-client-id", "x-cratis-token-scope", "x-cratis-tenant-id", "tenant-id", "x-cratis-microservice", "service-id"];
        readonly HashSet<string> _nonces = new(StringComparer.Ordinal);

        [GeneratedRegex("^(?:0|[1-9][0-9]{0,18})$", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, 1000)]
        private static partial Regex TimestampFormat { get; }

        [GeneratedRegex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, 1000)]
        private static partial Regex AccountFormat { get; }

        [GeneratedRegex("%[0-9a-fA-F]{2}", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, 1000)]
        private static partial Regex PercentFormat { get; }

        internal bool Accept(HttpRequestMessage request)
        {
            try
            {
                var envelope = request.Headers.GetValues("x-cratis-forwarded-identity-signature").Single();
                var parts = envelope.Split('.');
                if (envelope.Length > 256 || parts.Length != 5 || parts[0] != "v2" || parts[1] != keyId
                    || !TimestampFormat.IsMatch(parts[2]))
                {
                    return false;
                }
                var timestamp = long.Parse(parts[2], CultureInfo.InvariantCulture);
                var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (timestamp < now - 60 || timestamp > now + 30 || Decode(parts[3]).Length != 16 || Decode(parts[4]).Length != 64) return false;
                var snapshot = new SortedDictionary<string, string>(StringComparer.Ordinal);
                var headers = request.Headers.NonValidated.Select(header => KeyValuePair.Create(header.Key, header.Value.AsEnumerable()));
                if (request.Content is not null) headers = headers.Concat(request.Content.Headers.NonValidated.Select(header => KeyValuePair.Create(header.Key, header.Value.AsEnumerable())));
                foreach (var header in headers)
                {
                    var name = header.Key.ToLowerInvariant();
                    if (!name.StartsWith("x-ms-client-principal", StringComparison.Ordinal) && !name.StartsWith("x-cratis-on-behalf", StringComparison.Ordinal)
                        && !_context.Contains(name) && !_routing.Contains(name) && !name.Equals(tenantHeader, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    var values = header.Value.ToArray();
                    if (values.Length != 1 || !snapshot.TryAdd(name, values[0].Trim(' ', '\t')) || snapshot.Count > 64
                        || snapshot[name].Any(character => character < 32 || character > 126))
                    {
                        return false;
                    }
                }
                if (snapshot["x-cratis-credential-kind"] != "browser-session" || snapshot["x-cratis-sender-binding"] != "none"
                    || snapshot["x-cratis-issuer"] != BrowserSessionFixture.Realm || snapshot["x-cratis-idp"] != "https://upstream.example/"
                    || snapshot["x-cratis-auth-time"] != "1700000000" || snapshot["x-cratis-acr"] != "basic"
                    || !Guid.TryParseExact(snapshot["x-cratis-credential-id"], "D", out var credential) || credential == Guid.Empty
                    || !AccountFormat.IsMatch(snapshot["x-cratis-subject"])
                    || snapshot.Keys.Any(name => name.StartsWith("x-cratis-on-behalf", StringComparison.Ordinal) || name == "x-cratis-act" || name == "x-cratis-grant-id" || name == "x-cratis-bearer-sha256"))
                {
                    return false;
                }
                using var principal = JsonDocument.Parse(Convert.FromBase64String(snapshot["x-ms-client-principal"]));
                if (principal.RootElement.GetProperty("userId").GetString() != snapshot["x-cratis-subject"] || snapshot["x-ms-client-principal-id"] != snapshot["x-cratis-subject"]
                    || snapshot["x-ms-client-principal-name"].Length == 0)
                {
                    return false;
                }
                var path = request.RequestUri!.AbsolutePath;
                path = PercentFormat.Replace(path, match => match.Value.ToUpperInvariant());
                var canonical = new StringBuilder("Cratis.AuthProxy.ForwardedIdentity.v2\n");
                foreach (var value in new[] { audience, keyId, parts[2], parts[3], request.Method.Method, path, snapshot.Count.ToString(CultureInfo.InvariantCulture) }) Frame(canonical, value);
                foreach (var header in snapshot)
                {
                    Frame(canonical, header.Key);
                    Frame(canonical, header.Value);
                }
                var input = Encoding.UTF8.GetBytes(canonical.ToString());
                if (input.Length > 32768) return false;
                using var verifier = ECDsa.Create();
                verifier.ImportSubjectPublicKeyInfo(publicKey, out _);
                return verifier.VerifyData(input, Decode(parts[4]), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation) && _nonces.Add(parts[3]);
            }
            catch (Exception error) when (error is ArgumentException or FormatException or InvalidOperationException or KeyNotFoundException or JsonException or CryptographicException or OverflowException)
            {
                return false;
            }
        }

        static void Frame(StringBuilder builder, string value) => builder.Append(Encoding.UTF8.GetByteCount(value).ToString(CultureInfo.InvariantCulture)).Append(':').Append(value).Append('\n');

        static byte[] Decode(string text)
        {
            if (text.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_')) throw new FormatException();
            var bytes = Convert.FromBase64String(text.Replace('-', '+').Replace('_', '/') + new string('=', (4 - (text.Length % 4)) % 4));
            if (Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') != text) throw new FormatException();
            return bytes;
        }
    }
}
