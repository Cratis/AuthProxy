// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace Cratis.AuthProxy.BearerRoutes.TokenExchange;

/// <summary>Strictly reads Identity's bounded token-response contract without exposing its descriptions.</summary>
internal static partial class TokenExchangeResponse
{
    static readonly HashSet<string> _successFields = ["access_token", "token_type", "issued_token_type", "expires_in"];
    static readonly HashSet<string> _errorFields = ["error", "error_description", "error_uri"];

    [GeneratedRegex(@"\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z", RegexOptions.CultureInvariant, 100)]
    private static partial Regex JwtPattern { get; }

    /// <summary>Reads only the bounded documented response contract.</summary>
    /// <param name="response">The Identity response.</param>
    /// <param name="cancellationToken">The bounded call's cancellation signal.</param>
    /// <returns>A sanitized exchange outcome.</returns>
    internal static async Task<TokenExchangeResult> Read(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var retry = RetryAfter(response);
        if (IsUnavailable(response.StatusCode)) return new(TokenExchangeVerdict.Unavailable, retryAfter: retry);
        if (!string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)) return new(TokenExchangeVerdict.Refused);
        var bytes = await Body(response.Content, cancellationToken);
        if (bytes is null) return new(TokenExchangeVerdict.Refused);
        try
        {
            return Parse(bytes, response.StatusCode, retry);
        }
        catch (JsonException)
        {
            return new(TokenExchangeVerdict.Refused);
        }
    }

    static bool IsUnavailable(HttpStatusCode status) => status == HttpStatusCode.TooManyRequests || (int)status >= 500;

    static TokenExchangeResult Parse(byte[] bytes, HttpStatusCode status, int? retry)
    {
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || HasDuplicates(root)) return new(TokenExchangeVerdict.Refused);
        if (status == HttpStatusCode.OK) return Success(root);
        return IsTemporary(root) ? new(TokenExchangeVerdict.Unavailable, retryAfter: retry) : new(TokenExchangeVerdict.Refused);
    }

    static TokenExchangeResult Success(JsonElement root)
    {
        if (!SuccessFields(root)) return new(TokenExchangeVerdict.Refused);
        var seconds = Lifetime(root);
        if (seconds is null) return new(TokenExchangeVerdict.Refused);
        var token = Text(root, "access_token");
        return IsJwt(token) ? new(TokenExchangeVerdict.Success, token, seconds.Value) : new(TokenExchangeVerdict.Refused);
    }

    static bool SuccessFields(JsonElement root) => root.EnumerateObject().All(_ => _successFields.Contains(_.Name))
        && string.Equals(Text(root, "token_type"), "Bearer", StringComparison.OrdinalIgnoreCase) && AccessTokenType(root);

    static bool AccessTokenType(JsonElement root) => !root.TryGetProperty("issued_token_type", out _) || Text(root, "issued_token_type") == "urn:ietf:params:oauth:token-type:access_token";

    static int? Lifetime(JsonElement root)
    {
        if (!root.TryGetProperty("expires_in", out var lifetime)) return null;
        if (lifetime.ValueKind != JsonValueKind.Number || !lifetime.TryGetInt32(out var seconds)) return null;
        return seconds is >= 1 and <= 300 ? seconds : null;
    }

    static bool IsJwt(string? token) => token is not null && JwtPattern.IsMatch(token);

    static bool HasDuplicates(JsonElement root) => root.EnumerateObject().Select(_ => _.Name).Distinct(StringComparer.Ordinal).Count() != root.EnumerateObject().Count();

    static bool IsTemporary(JsonElement root) => root.EnumerateObject().All(_ => _errorFields.Contains(_.Name) && _.Value.ValueKind == JsonValueKind.String)
        && Text(root, "error") == "temporarily_unavailable";

    static string? Text(JsonElement root, string name) => root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    static int? RetryAfter(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Retry-After", out var values)) return null;
        var entries = values.ToArray();
        return entries.Length == 1 ? ParseRetryAfter(entries[0]) : null;
    }

    static int? ParseRetryAfter(string value)
    {
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)) return null;
        return seconds is >= 0 and <= 60 ? seconds : null;
    }

    static async Task<byte[]?> Body(HttpContent content, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > IdentityTokenExchangeClient.MaximumResponseSize) return null;
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        var buffer = new byte[IdentityTokenExchangeClient.MaximumResponseSize + 1];
        var total = 0;
        while (total < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken);
            if (count == 0) return buffer[..total];
            total += count;
        }
        return null;
    }
}
