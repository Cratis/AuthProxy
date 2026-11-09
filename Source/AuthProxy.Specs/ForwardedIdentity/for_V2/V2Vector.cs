// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

static class V2Vector
{
    internal static JsonDocument Load() => JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "ForwardedIdentity/for_V2/Fixtures/vectors.json")));

    internal static IEnumerable<KeyValuePair<string, IEnumerable<string>>> Headers(JsonElement input) => input.GetProperty("headers").EnumerateArray()
        .Select(header => new KeyValuePair<string, IEnumerable<string>>(header.GetProperty("name").GetString()!, [header.GetProperty("value").GetString()!]));

    internal static string? Header(JsonElement input, string name) => Headers(input).FirstOrDefault(header => header.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value?.Single().Trim(' ', '\t');

    internal static ForwardedIdentityTrustedContext Context(JsonElement input)
    {
        var issuer = Header(input, "x-cratis-issuer");
        var subject = Header(input, "x-cratis-subject");
        var idp = Header(input, "x-cratis-idp");
        var authTime = Header(input, "x-cratis-auth-time");
        var acr = Header(input, "x-cratis-acr");
        ForwardedIdentityVerifiedBearer? bearer = null;
        if (input.TryGetProperty("verifiedBearer", out var verified) && verified.ValueKind == JsonValueKind.Object && verified.GetProperty("accepted").GetBoolean())
        {
            var authorization = Header(input, "Authorization");
            var key = verified.GetProperty("accountKey");
            bearer = new(authorization is { Length: >= 7 } ? authorization[7..] : string.Empty, verified.GetProperty("verifier").GetString()!, key.GetProperty("issuer").GetString()!, key.GetProperty("subject").GetString()!);
        }
        return new(Header(input, "x-cratis-credential-kind") ?? string.Empty, Header(input, "x-cratis-credential-id") ?? string.Empty, Header(input, "x-cratis-sender-binding") ?? string.Empty)
        {
            TrustedRealmIssuer = input.GetProperty("realmIssuer").GetString(),
            Person = issuer is not null || subject is not null || idp is not null || authTime is not null || acr is not null
                ? new(issuer ?? string.Empty, subject ?? string.Empty, idp ?? string.Empty, authTime ?? string.Empty, acr ?? string.Empty) : null,
            AuthenticationMethods = Header(input, "x-cratis-amr"),
            Actor = Header(input, "x-cratis-act"),
            GrantId = Header(input, "x-cratis-grant-id"),
            PolicyEpoch = Header(input, "x-cratis-policy-epoch"),
            TenantHeader = input.GetProperty("tenantHeader").GetString()!,
            Bearer = bearer
        };
    }

    internal static HttpRequestMessage Request(JsonElement input)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "https://backend.example/");
        foreach (var header in Headers(input)) request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        return request;
    }

    internal static bool Canonical(JsonElement vector, string[] envelope, out byte[] bytes)
    {
        var input = vector.GetProperty("inputs");
        return ForwardedIdentityV2CanonicalInput.TryCreate(input.GetProperty("method").GetString()!, input.GetProperty("path").GetString()!, Headers(input), input.GetProperty("aud").GetString()!, envelope[1], envelope[2], envelope[3], input.GetProperty("tenantHeader").GetString()!, out bytes);
    }
}
