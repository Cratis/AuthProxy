// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using Cratis.AuthProxy.BearerRoutes;
using Cratis.AuthProxy.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Calls the application's grant check: <c language="text">GET {backend}/.cratis/on-behalf/grants</c>.
/// </summary>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="attestations">The issuer of the signed token the call carries.</param>
/// <param name="httpClientFactory">The HTTP client factory.</param>
/// <param name="timeProvider">The source of the current time.</param>
/// <param name="logger">The logger.</param>
/// <remarks>
/// Only an explicit, well-formed affirmative is live. A JSON <c language="text">false</c>, a <c language="text">403</c> or a
/// <c language="text">404</c> is the application saying no. Anything else — a failure to call, a timeout, another status, a
/// body that does not follow the contract, a represented user other than the one asked about — is indeterminate,
/// and indeterminate is never treated as live.
/// </remarks>
public sealed class OnBehalfGrants(
    IOptionsMonitor<C.AuthProxy> config,
    IOnBehalfAttestations attestations,
    IHttpClientFactory httpClientFactory,
    TimeProvider timeProvider,
    ILogger<OnBehalfGrants> logger) : IOnBehalfGrants
{
    /// <summary>
    /// The largest grant-check answer AuthProxy reads.
    /// </summary>
    public const int MaximumResponseLength = 64 * 1024;

    static readonly string[] _builtInRoles = ["anonymous", "authenticated"];

    static readonly JsonSerializerOptions _serializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    /// <inheritdoc/>
    public async Task<OnBehalfGrant> Check(OnBehalfSession session, ClientPrincipal actor, CancellationToken cancellationToken)
    {
        var current = config.CurrentValue;
        if (!OnBehalfApplication.TryResolve(current, WellKnownPaths.OnBehalfGrants, out var endpoint))
        {
            logger.GrantCheckNotConfigured();
            return OnBehalfGrant.Indeterminate;
        }

        var target = new Uri(QueryHelpers.AddQueryString(endpoint.ToString(), new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["subject"] = session.Subject,
            ["issue"] = session.Issue,
            ["actor"] = session.Actor.UserId,
            ["session"] = session.SessionId,
        }));

        if (!attestations.TryIssueForCall(OnBehalfAttestationClaims.GrantCheckPurpose, session, HttpMethod.Get, target, [], out var token))
        {
            logger.GrantCheckCouldNotBeSigned();
            return OnBehalfGrant.Indeterminate;
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, target);
        OnBehalfApplication.AddHeaders(request, session, actor, token);

        using var bounded = OnBehalfApplication.Bounded(current, cancellationToken);
        try
        {
            using var client = httpClientFactory.CreateClient();
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, bounded.Token);
            if (response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Forbidden)
            {
                logger.GrantNotLive((int)response.StatusCode);
                return OnBehalfGrant.NotLive;
            }

            if (!response.IsSuccessStatusCode)
            {
                logger.GrantCheckUnsuccessful((int)response.StatusCode);
                return OnBehalfGrant.Indeterminate;
            }

            if (response.Content.Headers.ContentLength > MaximumResponseLength)
            {
                logger.GrantCheckAnswerUnreadable();
                return OnBehalfGrant.Indeterminate;
            }

            var body = await ReadBounded(response, bounded.Token);
            return body is null ? Unreadable() : Read(body, session);
        }
        catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException or IOException)
        {
            logger.GrantCheckFailed(exception);
            return OnBehalfGrant.Indeterminate;
        }
    }

    static async Task<string?> ReadBounded(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var buffer = new byte[MaximumResponseLength + 1];
        var read = 0;
        int chunk;
        while (read < buffer.Length && (chunk = await stream.ReadAsync(buffer.AsMemory(read), cancellationToken)) > 0)
        {
            read += chunk;
        }

        return read > MaximumResponseLength ? null : System.Text.Encoding.UTF8.GetString(buffer, 0, read);
    }

    static bool? ReadBoolean(JsonObject parsed, string name) =>
        parsed.FirstOrDefault(_ => string.Equals(_.Key, name, StringComparison.OrdinalIgnoreCase)).Value is JsonValue value
            && value.TryGetValue<bool>(out var result)
            ? result
            : null;

    static JsonNode? ReadProperty(JsonObject parsed, string name) =>
        parsed.FirstOrDefault(_ => string.Equals(_.Key, name, StringComparison.OrdinalIgnoreCase)).Value;

    static ClientPrincipal Normalize(ClientPrincipal principal) => new()
    {
        IdentityProvider = string.IsNullOrWhiteSpace(principal.IdentityProvider) ? "unknown" : principal.IdentityProvider,
        UserId = principal.UserId,
        UserDetails = principal.UserDetails ?? string.Empty,
        UserRoles = (principal.UserRoles ?? []).Where(_ => !string.IsNullOrWhiteSpace(_)).Concat(_builtInRoles).Distinct(StringComparer.Ordinal).ToArray(),

        // The application identifies the represented user, but it does not get to say a request was authenticated on
        // a bearer route — that namespace is AuthProxy's alone, exactly as it is for a browser session's provider.
        Claims = (principal.Claims ?? [])
            .Where(_ => _ is not null && !string.IsNullOrEmpty(_.Type) && !BearerRouteClaims.IsReserved(_.Type))
            .ToArray(),
    };

    /// <summary>
    /// Reads an instant that states its offset.
    /// </summary>
    /// <param name="text">The ISO 8601 text.</param>
    /// <param name="instant">The instant.</param>
    /// <returns><see langword="true"/> when the text is a date and time with <c language="text">Z</c> or an explicit offset.</returns>
    /// <remarks>
    /// A date and time without an offset means a different instant on every machine that reads it, so a grant's
    /// validity would depend on the time zone AuthProxy happens to run in. It is refused rather than guessed at.
    /// </remarks>
    static bool TryReadInstant(string text, out DateTimeOffset instant)
    {
        instant = default;
        return DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
            && parsed.Kind != DateTimeKind.Unspecified
            && DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out instant);
    }

    OnBehalfGrant Unreadable()
    {
        logger.GrantCheckAnswerUnreadable();
        return OnBehalfGrant.Indeterminate;
    }

    OnBehalfGrant Read(string body, OnBehalfSession session)
    {
        JsonObject parsed;
        try
        {
            parsed = JsonNode.Parse(body) as JsonObject ?? throw new JsonException();
        }
        catch (JsonException)
        {
            return Unreadable();
        }

        // Only a JSON boolean is a verdict. Inferring one from a string or a number would be guessing at whether
        // somebody may act as another person.
        var live = ReadBoolean(parsed, "live");
        if (live is false)
        {
            logger.GrantNotLive(StatusCodes.Status200OK);
            return OnBehalfGrant.NotLive;
        }

        if (live is not true
            || ReadProperty(parsed, "validUntil") is not JsonValue validUntilValue
            || !validUntilValue.TryGetValue<string>(out var validUntilText)
            || !TryReadInstant(validUntilText, out var validUntil)
            || ReadProperty(parsed, "principal") is not JsonObject principalNode)
        {
            return Unreadable();
        }

        ClientPrincipal? principal;
        try
        {
            principal = principalNode.Deserialize<ClientPrincipal>(_serializerOptions);
        }
        catch (JsonException)
        {
            return Unreadable();
        }

        // The application must identify the very user the actor asked to represent. Any other answer is a contract
        // violation, and forwarding it would make the actor somebody nobody asked for.
        if (principal is null || !string.Equals(principal.UserId, session.Subject, StringComparison.Ordinal))
        {
            logger.GrantCheckNamedAnotherSubject();
            return OnBehalfGrant.Indeterminate;
        }

        if (validUntil <= timeProvider.GetUtcNow())
        {
            logger.GrantExpired();
            return OnBehalfGrant.Expired;
        }

        return OnBehalfGrant.Live(validUntil, Normalize(principal));
    }
}
