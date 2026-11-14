// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
sealed record TestKey(string Name, string[] KeyIds, string PrivateKeyPem, string PublicKeyPem);
sealed record Header(string Name, string Value);
sealed record Outcome(string Result, string Reason, [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? CallerSource = null);
sealed record AccountKey(string Issuer, string Subject);
sealed record VerifiedBearerResult(string Verifier, AccountKey AccountKey, bool Accepted = true);
sealed record Fixture(string Warning, string Format, TestKey[] TestKeys, List<Vector> Cases);
sealed record Inputs(
    string Method,
    string Path,
    string Aud,
    long Now,
    Header[] Headers,
    string TenantHeader = "x-example-tenant",
    bool ReplaySensitive = true,
    bool AuthenticatedTls = true,
    bool StoreAvailable = true,
    bool StoreFull = false,
    string Replica = "replica-a",
    string RealmIssuer = "https://identity.example.test",
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] VerifiedBearerResult? VerifiedBearer = null);
sealed record Vector(string Name, Inputs Inputs, string Envelope, string SigningInput, Outcome Expected, string? ReplayGroup = null);
sealed record CanonicalCheck(string? Bytes, string? Error);


sealed class Rejected(string reason) : Exception(reason);

sealed class NonceStore
{
    readonly Dictionary<(string Aud, string Kid, string Nonce), decimal> _reservations = [];

    public object[] Snapshot() => _reservations.Select(entry => (object)new { entry.Key.Aud, entry.Key.Kid, entry.Key.Nonce, ExpiresAt = entry.Value }).ToArray();

    public bool Reserve(string aud, string kid, string nonce, long timestamp, long now)
    {
        // Models one atomic insert and a shared durable store; not a production store implementation.
        foreach (var key in _reservations.Where(entry => entry.Value <= now).Select(entry => entry.Key).ToArray()) _reservations.Remove(key);
        return _reservations.TryAdd((aud, kid, nonce), (decimal)timestamp + 61);
    }
}

static partial class Reference
{
    [GeneratedRegex("\\A[A-Za-z0-9_-]{1,64}\\z", RegexOptions.None, 100)]
    private static partial Regex KeyIdPattern();

    [GeneratedRegex("\\A[A-Za-z0-9_-]+\\z", RegexOptions.None, 100)]
    private static partial Regex Base64UrlPattern();

    [GeneratedRegex("\\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\z", RegexOptions.None, 100)]
    private static partial Regex SubjectPattern();
    static readonly HashSet<string> ExactHeaders = new(StringComparer.Ordinal)
    {
        "x-cratis-token-client-id", "x-cratis-token-scope", "x-cratis-tenant-id", "tenant-id", "x-cratis-microservice", "service-id",
        "x-cratis-credential-kind", "x-cratis-credential-id", "x-cratis-issuer", "x-cratis-subject", "x-cratis-idp", "x-cratis-auth-time", "x-cratis-acr", "x-cratis-amr", "x-cratis-act", "x-cratis-grant-id", "x-cratis-policy-epoch", "x-cratis-sender-binding", "x-cratis-forwarded-token-sha256"
    };

    public static Outcome Verify(Vector vector, TestKey[] keys, NonceStore store)
    {
        try
        {
            var input = vector.Inputs;
            if (!input.AuthenticatedTls) throw new Rejected("hop");
            var envelope = Parse(vector.Envelope);
            if ((decimal)envelope.Timestamp < (decimal)input.Now - 60 || (decimal)envelope.Timestamp > (decimal)input.Now + 30) throw new Rejected("freshness");
            var key = keys.SingleOrDefault(candidate => candidate.KeyIds.Contains(envelope.Kid)) ?? throw new Rejected("key");
            var (canonical, headers) = Canonical(input, envelope.Parts);
            using var verifier = ECDsa.Create();
            verifier.ImportFromPem(key.PublicKeyPem);
            var verified = false;
            try { verified = verifier.VerifyData(canonical, envelope.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
            catch (CryptographicException) { /* Invalid scalars are a uniform signature rejection. */ }
            if (!verified) throw new Rejected("signature");
            Principal(headers);
            Metadata(headers, input.RealmIssuer);
            var callerSource = BindForwardedBearer(input, headers);
            if (input.ReplaySensitive)
            {
                if (!input.StoreAvailable || input.StoreFull) throw new Rejected("store");
                if (!store.Reserve(input.Aud, envelope.Kid, envelope.Parts[3], envelope.Timestamp, input.Now)) throw new Rejected("replay");
            }
            return new("accept", "ok", callerSource);
        }
        catch (Rejected error) { return new("reject", error.Message); }
    }

    public static string CanonicalFor(Vector vector) => Encoding.UTF8.GetString(Canonical(vector.Inputs, Parse(vector.Envelope).Parts).Bytes);

    public static CanonicalCheck CanonicalResult(Inputs input)
    {
        try { return new(Encoding.UTF8.GetString(Canonical(input, ["v2", "k1", "1700000000", "AAECAwQFBgcICQoLDA0ODw"]).Bytes), null); }
        catch (Rejected error) { return new(null, error.Message); }
    }

    static (string[] Parts, string Kid, long Timestamp, byte[] Signature) Parse(string text)
    {
        if (text.Length is 0 or > 256 || text.Any(c => c <= 32 || c >= 127)) throw new Rejected("format");
        var parts = text.Split('.');
        if (parts.Length != 5) throw new Rejected("format");
        if (parts[0] != "v2") throw new Rejected("version");
        if (!KeyIdPattern().IsMatch(parts[1]) || !Unsigned(parts[2], out var timestamp)) throw new Rejected("format");
        _ = DecodeUrl(parts[3], 16);
        return (parts, parts[1], timestamp, DecodeUrl(parts[4], 64));
    }

    static byte[] DecodeUrl(string value, int size)
    {
        if (!Base64UrlPattern().IsMatch(value) || value.Length != (size * 8 + 5) / 6) throw new Rejected("format");
        byte[] bytes;
        try { bytes = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4)); }
        catch (FormatException) { throw new Rejected("format"); }
        var encoded = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        if (bytes.Length != size || encoded != value) throw new Rejected("format");
        return bytes;
    }

    // Consumer implementation: streaming frames, independent selection and path handling.
    static (byte[] Bytes, SortedDictionary<string, string> Headers) Canonical(Inputs input, string[] parts)
    {
        if (input.Aud.Length is < 1 or > 64 || input.Aud[0] is < 'a' or > 'z' || input.Aud.Any(c => !(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')) || input.Aud.Split('-').Any(segment => segment.Length == 0)) throw new Rejected("request");
        const string methodToken = "!#$%&'*+-.^_`|~";
        if (input.Method.Length == 0 || input.Method.Any(c => !(c is >= 'A' and <= 'Z' or >= '0' and <= '9') && !methodToken.Contains(c))) throw new Rejected("request");
        if (!input.Path.StartsWith('/') || input.Path.Any(c => c < 33 || c > 126 || c == '#')) throw new Rejected("request");
        var query = input.Path.IndexOf('?');
        var path = (query < 0 ? input.Path : input.Path[..query]).ToCharArray();
        for (var i = 0; i < path.Length; i++)
        {
            if (path[i] != '%') continue;
            if (i + 2 >= path.Length || !Uri.IsHexDigit(path[i + 1]) || !Uri.IsHexDigit(path[i + 2])) throw new Rejected("request");
            path[++i] = char.ToUpperInvariant(path[i]);
            path[++i] = char.ToUpperInvariant(path[i]);
        }
        var headers = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var header in input.Headers)
        {
            var name = header.Name.ToLowerInvariant();
            if (name == "x-cratis-forwarded-identity-signature") continue;
            if (!name.StartsWith("x-ms-client-principal", StringComparison.Ordinal) && !name.StartsWith("x-cratis-on-behalf", StringComparison.Ordinal) && !ExactHeaders.Contains(name) && !name.Equals(input.TenantHeader, StringComparison.OrdinalIgnoreCase)) continue;
            if (header.Name.Length == 0 || header.Name.Any(c => !(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9') && !methodToken.Contains(c))) throw new Rejected("headers");
            var value = header.Value.Trim(' ', '\t');
            if (value.Any(c => c < 32 || c > 126) || !headers.TryAdd(name, value)) throw new Rejected("headers");
        }
        if (headers.Count > 64) throw new Rejected("bounds");
        foreach (var required in new[] { "x-ms-client-principal", "x-ms-client-principal-id", "x-ms-client-principal-name" })
        {
            if (!headers.TryGetValue(required, out var value) || value.Length == 0) throw new Rejected("headers");
        }
        using var stream = new MemoryStream();
        stream.Write(Encoding.UTF8.GetBytes("Cratis.AuthProxy.ForwardedIdentity.v2\n"));
        void Write(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            stream.Write(Encoding.ASCII.GetBytes(bytes.Length.ToString(CultureInfo.InvariantCulture) + ":"));
            stream.Write(bytes);
            stream.WriteByte(10);
            if (stream.Length > 32768) throw new Rejected("bounds");
        }
        foreach (var value in new[] { input.Aud, parts[1], parts[2], parts[3], input.Method, new string(path), headers.Count.ToString(CultureInfo.InvariantCulture) }) Write(value);
        foreach (var entry in headers) { Write(entry.Key); Write(entry.Value); }
        return (stream.ToArray(), headers);
    }

    static void Principal(SortedDictionary<string, string> headers)
    {
        try
        {
            var principalBytes = Convert.FromBase64String(headers["x-ms-client-principal"]);
            var text = new UTF8Encoding(false, true).GetString(principalBytes);
            using var document = JsonDocument.Parse(text);
            var root = document.RootElement;
            if (!root.TryGetProperty("userId", out var subject) || subject.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(subject.GetString()) ||
                !root.TryGetProperty("userRoles", out var roles) || roles.ValueKind != JsonValueKind.Array || roles.EnumerateArray().Any(role => role.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(role.GetString())) ||
                !root.TryGetProperty("claims", out var claims) || claims.ValueKind != JsonValueKind.Array || claims.EnumerateArray().Any(claim => claim.ValueKind != JsonValueKind.Object || !claim.TryGetProperty("typ", out var type) || type.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(type.GetString()) || !claim.TryGetProperty("val", out var value) || value.ValueKind != JsonValueKind.String)) throw new Rejected("identity");
            var id = headers["x-ms-client-principal-id"];
            if (id.StartsWith("UTF-8''", StringComparison.OrdinalIgnoreCase))
            {
                var bytes = new List<byte>();
                for (var i = 7; i < id.Length; i++)
                {
                    if (id[i] != '%') { bytes.Add((byte)id[i]); continue; }
                    if (i + 2 >= id.Length || !Uri.IsHexDigit(id[i + 1]) || !Uri.IsHexDigit(id[i + 2])) throw new Rejected("identity");
                    bytes.Add(Convert.ToByte(id.Substring(i + 1, 2), 16));
                    i += 2;
                }
                id = new UTF8Encoding(false, true).GetString(bytes.ToArray());
            }
            if (id != subject.GetString()) throw new Rejected("identity");
            var service = headers.GetValueOrDefault("x-cratis-credential-kind") is "machine-principal" or "workload";
            if (!service && !SubjectPattern().IsMatch(id)) throw new Rejected("identity");
            if (!service && headers.TryGetValue("x-cratis-subject", out var explicitSubject) && explicitSubject.Length > 0 && explicitSubject != id) throw new Rejected("identity");
        }
        catch (Exception error) when (error is FormatException or JsonException or DecoderFallbackException or InvalidOperationException) { throw new Rejected("identity"); }
    }

    static void Metadata(SortedDictionary<string, string> headers, string realmIssuer)
    {
        try
        {
            var kind = Required(headers, "x-cratis-credential-kind");
            if (kind is not ("browser-session" or "oauth-grant" or "pat" or "on-behalf-session" or "machine-principal" or "workload")) throw new Rejected("metadata");
            _ = Required(headers, "x-cratis-credential-id");
            var service = kind is "machine-principal" or "workload";
            if (!service)
            {
                if (Required(headers, "x-cratis-issuer") != realmIssuer) throw new Rejected("metadata");
                _ = Required(headers, "x-cratis-subject");
                _ = Required(headers, "x-cratis-idp");
                if (!NumericDate(Required(headers, "x-cratis-auth-time"))) throw new Rejected("metadata");
                _ = Required(headers, "x-cratis-acr");
            }
            else if (headers.Keys.Any(name => name is "x-cratis-issuer" or "x-cratis-subject" or "x-cratis-idp" or "x-cratis-auth-time" or "x-cratis-acr" or "x-cratis-amr" or "x-cratis-act")) throw new Rejected("metadata");
            foreach (var name in new[] { "x-cratis-idp", "x-cratis-auth-time", "x-cratis-acr", "x-cratis-amr", "x-cratis-act", "x-cratis-grant-id", "x-cratis-policy-epoch" })
            {
                if (headers.TryGetValue(name, out var value) && value.Length == 0) throw new Rejected("metadata");
            }
            if (headers.TryGetValue("x-cratis-policy-epoch", out var epoch) && !Unsigned(epoch, out _)) throw new Rejected("metadata");
            if (headers.TryGetValue("x-cratis-amr", out var methods))
            {
                using var document = DecodeJson(methods);
                if (document.RootElement.ValueKind != JsonValueKind.Array || document.RootElement.EnumerateArray().Any(method => method.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(method.GetString()))) throw new Rejected("metadata");
            }
            if (kind == "on-behalf-session") _ = Required(headers, "x-cratis-act");
            if (headers.TryGetValue("x-cratis-act", out var actor))
            {
                using var document = DecodeJson(actor);
                CheckActor(document.RootElement, 0);
                _ = Required(headers, "x-cratis-grant-id");
            }
            var binding = Required(headers, "x-cratis-sender-binding");
            if (binding != "none")
            {
                using var document = DecodeJson(binding);
                var evidence = document.RootElement;
                if (evidence.ValueKind != JsonValueKind.Object || evidence.EnumerateObject().Count() != 2 || !StringField(evidence, "jkt") || !StringField(evidence, "jti")) throw new Rejected("metadata");
                try { _ = DecodeUrl(evidence.GetProperty("jkt").GetString()!, 32); }
                catch (Rejected) { throw new Rejected("metadata"); }
            }
        }
        catch (Exception error) when (error is FormatException or JsonException or DecoderFallbackException or InvalidOperationException) { throw new Rejected("metadata"); }
    }

    static bool NumericDate(string value) => long.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var timestamp) && value == timestamp.ToString(CultureInfo.InvariantCulture);

    [GeneratedRegex("^[a-z0-9-]+_pat_", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex PatNamespace();

    static string? BindForwardedBearer(Inputs input, SortedDictionary<string, string> headers)
    {
        var authorization = input.Headers.Where(header => header.Name.Equals("Authorization", StringComparison.OrdinalIgnoreCase)).ToArray();
        var hasHash = headers.TryGetValue("x-cratis-forwarded-token-sha256", out var hash);
        if (authorization.Length == 0)
        {
            if (hasHash) throw new Rejected("credential");
            return null;
        }
        if (authorization.Length != 1 || !hasHash || !authorization[0].Value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) throw new Rejected("credential");
        var token = authorization[0].Value[7..];
        var unpadded = token.TrimEnd('=');
        if (unpadded.Length == 0 || unpadded.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '.' or '_' or '~' or '+' or '/'))) throw new Rejected("credential");
        byte[] expected;
        try { expected = DecodeUrl(hash!, 32); }
        catch (Rejected) { throw new Rejected("credential"); }
        if (!CryptographicOperations.FixedTimeEquals(expected, SHA256.HashData(Encoding.UTF8.GetBytes(token)))) throw new Rejected("credential");
        return VerifiedBearerCallerSource(input, headers, PatNamespace().IsMatch(token));
    }

    static string VerifiedBearerCallerSource(Inputs input, SortedDictionary<string, string> headers, bool patNamespace)
    {
        if (patNamespace && headers["x-cratis-credential-kind"] != "pat") throw new Rejected("credential");
        var callerSource = patNamespace ? "pat-verifier" : "oauth-verifier";
        // Injected result of verifying this exact bearer, not authority derived from signed headers.
        var bearer = input.VerifiedBearer;
        if (bearer?.Accepted != true || bearer.Verifier != callerSource) throw new Rejected("credential");
        // Principal already requires both nonempty signed account-key fields.
        var signedAccountKey = new AccountKey(headers.GetValueOrDefault("x-cratis-issuer", ""), headers.GetValueOrDefault("x-cratis-subject", ""));
        if (signedAccountKey != bearer.AccountKey) throw new Rejected("credential");
        return callerSource;
    }

    static string Required(SortedDictionary<string, string> headers, string name) => headers.TryGetValue(name, out var value) && value.Length > 0 ? value : throw new Rejected("metadata");

    static JsonDocument DecodeJson(string value) => JsonDocument.Parse(new UTF8Encoding(false, true).GetString(Convert.FromBase64String(value)));

    static bool StringField(JsonElement element, string name) => element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString());

    static void CheckActor(JsonElement actor, int depth)
    {
        if (depth > 8 || actor.ValueKind != JsonValueKind.Object || !StringField(actor, "iss") || !StringField(actor, "sub") || actor.EnumerateObject().Any(field => field.Name is not ("iss" or "sub" or "act"))) throw new Rejected("metadata");
        if (actor.TryGetProperty("act", out var previous)) CheckActor(previous, depth + 1);
    }

    static bool Unsigned(string value, out long number) => long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out number) && value.Length <= 19 && value == number.ToString(CultureInfo.InvariantCulture);
}
