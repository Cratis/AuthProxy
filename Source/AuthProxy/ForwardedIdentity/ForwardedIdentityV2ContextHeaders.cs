// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Projects and checks verified v2 evidence without trusting inbound context headers.</summary>
internal static partial class ForwardedIdentityV2ContextHeaders
{
    /// <summary>The exact v2 context header names.</summary>
    internal static readonly string[] Names =
    [
        "x-cratis-credential-kind", "x-cratis-credential-id", "x-cratis-issuer", "x-cratis-subject", "x-cratis-idp",
        "x-cratis-auth-time", "x-cratis-acr", "x-cratis-amr", "x-cratis-act", "x-cratis-grant-id",
        "x-cratis-policy-epoch", "x-cratis-sender-binding", "x-cratis-forwarded-token-sha256"
    ];

    [GeneratedRegex("\\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\z", RegexOptions.None, 100)]
    private static partial Regex SubjectPattern { get; }

    [GeneratedRegex("^[a-z0-9-]+_pat_", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex PatNamespace { get; }

    /// <summary>Replaces inbound context headers only after validating independent evidence.</summary>
    /// <param name="request">The final outbound request.</param>
    /// <param name="context">Evidence supplied by the trusted pipeline.</param>
    /// <returns>Whether verified context could be applied.</returns>
    internal static bool TryApply(HttpRequestMessage request, ForwardedIdentityTrustedContext context)
    {
        if (!ForwardedIdentityV2CanonicalInput.HasBoundedSnapshot(request, context.TenantHeader)
            || !TryHeaders(context, out var headers) || !PrincipalMatches(request, context) || !BearerMatches(request, context))
        {
            return false;
        }
        foreach (var name in Names) request.Headers.Remove(name);
        foreach (var header in headers) request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        return true;
    }

    /// <summary>Checks that the final snapshot agrees with independent verified evidence.</summary>
    /// <param name="request">The final outbound request.</param>
    /// <param name="context">Evidence supplied by the trusted pipeline.</param>
    /// <returns>Whether all context and identity bindings agree.</returns>
    internal static bool Matches(HttpRequestMessage request, ForwardedIdentityTrustedContext context)
    {
        if (!ForwardedIdentityV2CanonicalInput.HasBoundedSnapshot(request, context.TenantHeader)
            || !TryHeaders(context, out var expected) || !PrincipalMatches(request, context) || !BearerMatches(request, context))
        {
            return false;
        }
        foreach (var name in Names)
        {
            var present = request.Headers.NonValidated.TryGetValues(name, out var values);
            if (expected.TryGetValue(name, out var value))
            {
                if (!present || values.Count != 1 || values.Single().Trim(' ', '\t') != value) return false;
            }
            else if (present)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>Projects structurally valid context into the v2 header allowlist.</summary>
    /// <param name="context">Independent verified evidence.</param>
    /// <param name="headers">The projected covered metadata.</param>
    /// <returns>Whether all required evidence is available and well formed.</returns>
    internal static bool TryHeaders(ForwardedIdentityTrustedContext context, out Dictionary<string, string> headers)
    {
        headers = new(StringComparer.Ordinal);
        if (context.CredentialKind is not ("browser-session" or "on-behalf-session" or "oauth-grant" or "pat" or "machine-principal" or "workload")
            || string.IsNullOrEmpty(context.CredentialId) || string.IsNullOrEmpty(context.SenderBinding))
        {
            return false;
        }

        headers[Names[0]] = context.CredentialKind;
        headers[Names[1]] = context.CredentialId;
        headers[Names[11]] = context.SenderBinding;
        var service = context.CredentialKind == "machine-principal" || context.CredentialKind == "workload";
        if (service)
        {
            if (context.Person is not null || context.AuthenticationMethods is not null || context.Actor is not null) return false;
        }
        else
        {
            if (context.Person is not { } person || !SubjectPattern.IsMatch(person.Subject)
                || person.Issuer != context.TrustedRealmIssuer || !Uri.TryCreate(person.Issuer, UriKind.Absolute, out var issuer) || issuer.Scheme != Uri.UriSchemeHttps
                || string.IsNullOrEmpty(person.IdentityProvider) || person.AuthenticationContext != "basic" || !NumericDate(person.AuthenticationTime))
            {
                return false;
            }

            headers[Names[2]] = person.Issuer;
            headers[Names[3]] = person.Subject;
            headers[Names[4]] = person.IdentityProvider;
            headers[Names[5]] = person.AuthenticationTime;
            headers[Names[6]] = person.AuthenticationContext;
        }
        if (context.CredentialKind == "on-behalf-session" && (context.Actor is null || context.GrantId is null)) return false;
        if (context.Actor is not null && context.GrantId is null) return false;
        if (context.PolicyEpoch is not null && (!NumericDate(context.PolicyEpoch) || context.PolicyEpoch.StartsWith('-'))) return false;
        if (context.AuthenticationMethods is not null) headers[Names[7]] = context.AuthenticationMethods;
        if (context.Actor is not null) headers[Names[8]] = context.Actor;
        if (context.GrantId is not null) headers[Names[9]] = context.GrantId;
        if (context.PolicyEpoch is not null) headers[Names[10]] = context.PolicyEpoch;
        if (context.Bearer is not null) headers[Names[12]] = ForwardedIdentityV2Envelope.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(context.Bearer.Token)));
        if (headers.Values.Any(value => value.Length == 0 || value.Any(character => character < 32 || character > 126))) return false;
        return JsonEvidence(context);
    }

    static bool JsonEvidence(ForwardedIdentityTrustedContext context)
    {
        try
        {
            if (context.AuthenticationMethods is not null)
            {
                using var methods = DecodeJson(context.AuthenticationMethods);
                if (methods.RootElement.ValueKind != JsonValueKind.Array || methods.RootElement.EnumerateArray().Any(method => method.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(method.GetString()))) return false;
            }
            if (context.Actor is not null)
            {
                using var actor = DecodeJson(context.Actor);
                if (!ValidActor(actor.RootElement, 0)) return false;
            }
            if (context.SenderBinding != "none")
            {
                using var binding = DecodeJson(context.SenderBinding);
                var root = binding.RootElement;
                if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 2 || !StringField(root, "jkt") || !StringField(root, "jti")
                    || !ForwardedIdentityV2Envelope.IsBase64Url(root.GetProperty("jkt").GetString()!, 32))
                {
                    return false;
                }
            }
            return true;
        }
        catch (Exception error) when (error is FormatException or JsonException or DecoderFallbackException or InvalidOperationException)
        {
            return false;
        }
    }

    static bool PrincipalMatches(HttpRequestMessage request, ForwardedIdentityTrustedContext context)
    {
        if (!request.Headers.NonValidated.TryGetValues(Headers.Principal, out var values) || values.Count != 1
            || !request.Headers.NonValidated.TryGetValues(Headers.PrincipalId, out var ids) || ids.Count != 1)
        {
            return false;
        }

        try
        {
            using var principal = DecodeJson(values.Single().Trim(' ', '\t'));
            var root = principal.RootElement;
            if (!StringField(root, "userId") || !root.TryGetProperty("userRoles", out var roles) || roles.ValueKind != JsonValueKind.Array
                || roles.EnumerateArray().Any(role => role.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(role.GetString()))
                || !root.TryGetProperty("claims", out var claims) || claims.ValueKind != JsonValueKind.Array
                || claims.EnumerateArray().Any(claim => claim.ValueKind != JsonValueKind.Object || !StringField(claim, "typ") || !claim.TryGetProperty("val", out var value) || value.ValueKind != JsonValueKind.String))
            {
                return false;
            }

            var id = ids.Single().Trim(' ', '\t');
            if (id.StartsWith("UTF-8''", StringComparison.OrdinalIgnoreCase))
            {
                var bytes = new List<byte>();
                for (var index = 7; index < id.Length; index++)
                {
                    if (id[index] != '%')
                    {
                        bytes.Add(checked((byte)id[index]));
                        continue;
                    }
                    if (index + 2 >= id.Length || !Uri.IsHexDigit(id[index + 1]) || !Uri.IsHexDigit(id[index + 2])) return false;
                    bytes.Add(Convert.ToByte(id.Substring(index + 1, 2), 16));
                    index += 2;
                }
                id = new UTF8Encoding(false, true).GetString(bytes.ToArray());
            }
            return id == root.GetProperty("userId").GetString() && (context.Person is null || id == context.Person.Subject);
        }
        catch (Exception error) when (error is FormatException or JsonException or DecoderFallbackException or InvalidOperationException or OverflowException)
        {
            return false;
        }
    }

    static bool BearerMatches(HttpRequestMessage request, ForwardedIdentityTrustedContext context)
    {
        if (!request.Headers.NonValidated.TryGetValues("Authorization", out var authorization)) return context.Bearer is null;
        if (authorization.Count != 1 || context.Bearer is not { } bearer || context.Person is not { } person) return false;
        var value = authorization.Single();
        if (!value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) || value[7..] != bearer.Token
            || bearer.Token.TrimEnd('=').Length == 0 || bearer.Token.TrimEnd('=').Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('-' or '.' or '_' or '~' or '+' or '/'))
            || bearer.Issuer != person.Issuer || bearer.Subject != person.Subject)
        {
            return false;
        }

        var pat = PatNamespace.IsMatch(bearer.Token);
        return bearer.Verifier == (pat ? "pat-verifier" : "oauth-verifier") && (!pat || context.CredentialKind == "pat");
    }

    static bool NumericDate(string value) => long.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var timestamp) && value == timestamp.ToString(CultureInfo.InvariantCulture);
    static JsonDocument DecodeJson(string value) => JsonDocument.Parse(new UTF8Encoding(false, true).GetString(Convert.FromBase64String(value)));
    static bool StringField(JsonElement element, string name) => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString());
    static bool ValidActor(JsonElement actor, int depth) => depth <= 8 && StringField(actor, "iss") && StringField(actor, "sub")
        && actor.EnumerateObject().All(field => field.Name == "iss" || field.Name == "sub" || field.Name == "act") && (!actor.TryGetProperty("act", out var previous) || ValidActor(previous, depth + 1));
}
