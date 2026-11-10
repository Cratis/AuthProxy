// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes.Introspection;

/// <summary>
/// Asks an issuer's RFC 7662 introspection endpoint whether an access token is still active.
/// </summary>
/// <param name="httpClientFactory">The factory for the hardened introspection client.</param>
/// <param name="cache">The cache of active answers.</param>
/// <param name="timeProvider">The clock.</param>
/// <param name="logger">The logger.</param>
/// <remarks>
/// Only whether the token is active is taken from the answer; no claim in it reaches the principal. An answer that
/// names a different subject, issuer, client or token type than the validated token is treated as inactive. Only
/// a well-formed <c language="text">200</c> answer says anything about the token; every other outcome is
/// <see cref="IntrospectionVerdict.Unavailable"/>, never "active" and never "inactive". Concurrent requests for the
/// same token and cache window share one call, made under a deadline of its own so one caller abandoning its request does not fail
/// the others. Nothing here logs the token, its hash, the secret or the answer.
/// </remarks>
public sealed class BearerTokenIntrospector(
    IHttpClientFactory httpClientFactory,
    IntrospectionCache cache,
    TimeProvider timeProvider,
    ILogger<BearerTokenIntrospector> logger) : IBearerTokenIntrospector
{
    const long MaximumUnixSeconds = 253_402_300_799;

    static readonly Answer _unavailable = new(IntrospectionVerdict.Unavailable, TimeSpan.MaxValue);
    static readonly Answer _inactive = new(IntrospectionVerdict.Inactive, TimeSpan.MaxValue);

    readonly ConcurrentDictionary<string, Lazy<Task<IntrospectionVerdict>>> _flights = new(StringComparer.Ordinal);

    /// <inheritdoc/>
    public async Task<IntrospectionVerdict> Introspect(string token, BearerTokenValidation validated, ResolvedBearerIssuer issuer, CancellationToken cancellationToken)
    {
        if (issuer.Introspection is not { } settings)
        {
            return IntrospectionVerdict.Unavailable;
        }

        // Neither cached answers nor in-flight calls may cross cache-window policies.
        var cacheDuration = Min(settings.CacheDuration, C.BearerIssuerIntrospection.MaximumCacheDuration);
        var key = string.Create(CultureInfo.InvariantCulture, $"{IntrospectionCache.CreateKey(settings.Endpoint, settings.ClientId, token)}:{cacheDuration.Ticks}");
        if (cache.IsActive(key))
        {
            return IntrospectionVerdict.Active;
        }

        var flight = _flights.GetOrAdd(
            key,
            static (flightKey, state) => new Lazy<Task<IntrospectionVerdict>>(() => state.Introspector.Ask(flightKey, state.Token, state.Validated, state.Issuer, state.Settings)),
            new FlightState(this, token, validated, issuer, settings));
        return await flight.Value.WaitAsync(cancellationToken);
    }

    static bool TryReadInstant(JsonElement element, out DateTimeOffset instant)
    {
        instant = default;
        if (TryReadSeconds(element, out var seconds) && seconds is > 0 and <= MaximumUnixSeconds)
        {
            instant = DateTimeOffset.FromUnixTimeSeconds(seconds);
            return true;
        }

        return false;
    }

    static bool Differs(JsonElement root, string name, string? expected, StringComparison comparison = StringComparison.Ordinal)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return false;
        }

        return value.ValueKind != JsonValueKind.String || !string.Equals(value.GetString(), expected, comparison);
    }

    static bool TryReadSeconds(JsonElement element, out long seconds)
    {
        seconds = default;
        return element.ValueKind == JsonValueKind.Number && element.TryGetInt64(out seconds);
    }

    static bool TryReadActive(JsonElement root, out JsonElement active)
    {
        active = default;
        return root.ValueKind == JsonValueKind.Object && root.TryGetProperty("active", out active)
            && active.ValueKind is JsonValueKind.True or JsonValueKind.False;
    }

    static string? FindContradiction(JsonElement root, BearerTokenValidation validated, ResolvedBearerIssuer issuer)
    {
        if (Dpop.DpopIntrospection.Contradiction(root, validated) is { } constraintReason)
        {
            return constraintReason;
        }

        var principal = validated.Principal;
        var clientId = principal?.FindFirst(BearerRouteClaims.ClientId)?.Value;
        if (Differs(root, "sub", principal?.FindFirst(BearerRouteClaims.Subject)?.Value))
        {
            return "sub";
        }

        if (Differs(root, "iss", issuer.Issuer))
        {
            return "iss";
        }

        if (Differs(root, "client_id", clientId))
        {
            return "client_id";
        }

        if (Differs(root, "azp", clientId))
        {
            return "azp";
        }

        return null;
    }

    static TimeSpan Min(TimeSpan first, TimeSpan second) => first < second ? first : second;

    static HttpRequestMessage CreateRequest(Uri endpoint, string token, C.BearerIssuerIntrospection settings)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("token", token),
                new KeyValuePair<string, string>("token_type_hint", "access_token"),
            ]),
        };

        // RFC 6749 section 2.3.1: client_secret_basic, id and secret form-urlencoded before the Basic encoding.
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(settings.ClientId)}:{Uri.EscapeDataString(settings.ClientSecret)}")));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return request;
    }

    async Task<IntrospectionVerdict> Ask(string key, string token, BearerTokenValidation validated, ResolvedBearerIssuer issuer, C.BearerIssuerIntrospection settings)
    {
        try
        {
            using var deadline = new CancellationTokenSource(settings.Timeout);
            var answer = await Query(token, validated, issuer, settings, deadline.Token);
            if (answer.Verdict == IntrospectionVerdict.Active)
            {
                var lifetime = Min(Min(settings.CacheDuration, C.BearerIssuerIntrospection.MaximumCacheDuration), answer.LifetimeLimit);
                cache.Store(key, Min(lifetime, TokenRemainingLifetime(validated)), settings.MaximumCachedTokens);
            }

            return answer.Verdict;
        }
        finally
        {
            _flights.TryRemove(key, out _);
        }
    }

    TimeSpan TokenRemainingLifetime(BearerTokenValidation validated)
    {
        var exp = validated.Principal?.FindFirst("exp")?.Value;
        return long.TryParse(exp, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) && seconds is > 0 and <= MaximumUnixSeconds
            ? DateTimeOffset.FromUnixTimeSeconds(seconds) - timeProvider.GetUtcNow()
            : TimeSpan.Zero;
    }

    async Task<Answer> Query(
        string token,
        BearerTokenValidation validated,
        ResolvedBearerIssuer issuer,
        C.BearerIssuerIntrospection settings,
        CancellationToken cancellationToken)
    {
        if (!BearerRouteTable.TryParseAuthorityUri(settings.Endpoint, out var endpoint, out _))
        {
            logger.IntrospectionUnavailable(issuer.Issuer, "InvalidEndpoint");
            return _unavailable;
        }

        try
        {
            using var request = CreateRequest(endpoint, token, settings);
            using var client = httpClientFactory.CreateClient(BearerRouteDefaults.IntrospectionHttpClientName);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                logger.IntrospectionClientRejected(issuer.Issuer, (int)response.StatusCode);
                return _unavailable;
            }

            if (response.StatusCode != HttpStatusCode.OK)
            {
                logger.IntrospectionUnavailable(issuer.Issuer, $"HTTP {(int)response.StatusCode / 100}xx");
                return _unavailable;
            }

            using var document = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(cancellationToken));
            return Interpret(document.RootElement, validated, issuer);
        }
        catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException or JsonException or InvalidOperationException)
        {
            logger.IntrospectionUnavailable(issuer.Issuer, exception.GetType().Name);
            return _unavailable;
        }
    }

    Answer Interpret(JsonElement root, BearerTokenValidation validated, ResolvedBearerIssuer issuer)
    {
        if (!TryReadActive(root, out var active))
        {
            logger.IntrospectionUnavailable(issuer.Issuer, "MalformedAnswer");
            return _unavailable;
        }

        if (active.ValueKind == JsonValueKind.False)
        {
            return _inactive;
        }

        var contradicted = FindContradiction(root, validated, issuer);
        if (contradicted is not null)
        {
            logger.IntrospectionMismatch(issuer.Issuer, contradicted);
            return _inactive;
        }

        var limit = root.TryGetProperty("exp", out var exp) && TryReadInstant(exp, out var expiresAt)
            ? expiresAt - timeProvider.GetUtcNow()
            : TimeSpan.MaxValue;
        return new Answer(IntrospectionVerdict.Active, limit);
    }

    sealed record FlightState(BearerTokenIntrospector Introspector, string Token, BearerTokenValidation Validated, ResolvedBearerIssuer Issuer, C.BearerIssuerIntrospection Settings);

    sealed record Answer(IntrospectionVerdict Verdict, TimeSpan LifetimeLimit);
}
