// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.AccessTokens;

/// <summary>
/// Represents an implementation of <see cref="IUserAccessTokens"/> that redeems the session's refresh token at the
/// identity provider's token endpoint (RFC 6749 section 6) for each audience, and caches the result until shortly
/// before it expires.
/// </summary>
/// <remarks>
/// AuthProxy authenticates the refresh the way it authenticates the sign-in: with the provider's client secret, or
/// with the client assertion of its certificate or federated credential. A provider that rotates refresh tokens gets
/// the new one stored. Refreshes for one session are serialized within this instance, so concurrent requests do
/// not race to redeem the same refresh token.
/// </remarks>
/// <param name="store">The <see cref="IUserTokenStore"/> holding refresh and access tokens.</param>
/// <param name="oidcOptions">The OIDC handler options, for each provider's client and metadata.</param>
/// <param name="authentication">The authentication configuration, for each provider's client credential.</param>
/// <param name="clientAssertions">The <see cref="IOidcClientAssertions"/> for providers authenticated by assertion.</param>
/// <param name="httpClientFactory">The <see cref="IHttpClientFactory"/> for the token endpoint.</param>
/// <param name="timeProvider">The <see cref="TimeProvider"/>.</param>
/// <param name="logger">The <see cref="ILogger"/> for diagnostics.</param>
public sealed class UserAccessTokens(
    IUserTokenStore store,
    IOptionsMonitor<OpenIdConnectOptions> oidcOptions,
    IOptionsMonitor<C.Authentication> authentication,
    IOidcClientAssertions clientAssertions,
    IHttpClientFactory httpClientFactory,
    TimeProvider timeProvider,
    ILogger<UserAccessTokens> logger) : IUserAccessTokens
{
    /// <summary>
    /// The name of the HTTP client used for the token endpoint.
    /// </summary>
    public const string HttpClientName = "Cratis.AuthProxy.UserAccessTokens";

    /// <summary>
    /// How long before its expiry a cached access token is renewed.
    /// </summary>
    public static readonly TimeSpan RenewalMargin = TimeSpan.FromMinutes(1);

    /// <summary>
    /// The lifetime assumed for an access token whose response states none.
    /// </summary>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(5);

    readonly SemaphoreSlim[] _refreshLocks = [.. Enumerable.Range(0, 64).Select(_ => new SemaphoreSlim(1, 1))];

    /// <inheritdoc/>
    public async Task<UserAccessTokenResult> GetFor(string sessionId, C.ServiceAccessToken accessToken, CancellationToken cancellationToken)
    {
        var session = await store.Get(sessionId, cancellationToken);
        if (session is null)
        {
            return UserAccessTokenResult.Failed(UserAccessTokenFailure.NoRefreshToken);
        }

        if (!string.IsNullOrWhiteSpace(accessToken.Provider)
            && !string.Equals(OidcProviderScheme.FromName(accessToken.Provider), session.Scheme, StringComparison.Ordinal))
        {
            return UserAccessTokenResult.Failed(UserAccessTokenFailure.WrongProvider);
        }

        var audience = AudienceKey(session.Scheme, accessToken);
        if (await UsableCachedToken(sessionId, audience, cancellationToken) is { } cached)
        {
            return UserAccessTokenResult.Success(cached);
        }

        var refreshLock = _refreshLocks[(uint)StringComparer.Ordinal.GetHashCode(sessionId) % (uint)_refreshLocks.Length];
        await refreshLock.WaitAsync(cancellationToken);
        try
        {
            // Another request for this session may have refreshed while this one waited.
            if (await UsableCachedToken(sessionId, audience, cancellationToken) is { } refreshed)
            {
                return UserAccessTokenResult.Success(refreshed);
            }

            session = await store.Get(sessionId, cancellationToken);
            return session is null
                ? UserAccessTokenResult.Failed(UserAccessTokenFailure.NoRefreshToken)
                : await Refresh(sessionId, session, audience, accessToken, cancellationToken);
        }
        finally
        {
            refreshLock.Release();
        }
    }

    static string AudienceKey(string scheme, C.ServiceAccessToken accessToken)
    {
        var scopes = string.Join(' ', accessToken.Scopes.Select(_ => _.Trim()).Where(_ => _.Length > 0).Order(StringComparer.Ordinal));
        var material = $"{scheme}\n{scopes}\n{accessToken.Resource.Trim()}";
        return WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }

    static string? StringProperty(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    static TimeSpan Lifetime(JsonElement root) =>
        root.TryGetProperty("expires_in", out var value) && value.ValueKind switch
        {
            JsonValueKind.Number => value.TryGetInt64(out var seconds) && seconds > 0 ? TimeSpan.FromSeconds(seconds) : (TimeSpan?)null,
            JsonValueKind.String => long.TryParse(value.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) && seconds > 0 ? TimeSpan.FromSeconds(seconds) : null,
            _ => null
        } is { } lifetime
            ? lifetime
            : DefaultLifetime;

    async Task<string?> UsableCachedToken(string sessionId, string audience, CancellationToken cancellationToken) =>
        await store.GetAccessToken(sessionId, audience, cancellationToken) is { } cached
        && cached.ExpiresAt - RenewalMargin > timeProvider.GetUtcNow()
            ? cached.Value
            : null;

    async Task<UserAccessTokenResult> Refresh(
        string sessionId,
        UserTokenSession session,
        string audience,
        C.ServiceAccessToken accessToken,
        CancellationToken cancellationToken)
    {
        var provider = authentication.CurrentValue.OidcProviders
            .FirstOrDefault(_ => string.Equals(OidcProviderScheme.FromName(_.Name), session.Scheme, StringComparison.Ordinal));
        if (provider is null)
        {
            logger.ProviderNoLongerConfigured(session.Scheme);
            return UserAccessTokenResult.Failed(UserAccessTokenFailure.ProviderUnavailable);
        }

        try
        {
            var options = oidcOptions.Get(session.Scheme);
            var tokenEndpoint = await OidcClientAuthentication.TokenEndpointOf(options, cancellationToken);
            using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
            {
                Content = new FormUrlEncodedContent(await Form(session, provider, options, accessToken, tokenEndpoint, cancellationToken))
            };
            request.Headers.Accept.ParseAdd("application/json");

            using var response = await httpClientFactory.CreateClient(HttpClientName).SendAsync(request, cancellationToken);
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            var root = document.RootElement;

            if (!response.IsSuccessStatusCode)
            {
                var error = root.ValueKind == JsonValueKind.Object ? StringProperty(root, "error") : null;
                logger.RefreshRefused(session.Scheme, (int)response.StatusCode, error ?? "(none)");
                if (string.Equals(error, "invalid_grant", StringComparison.Ordinal))
                {
                    await store.Remove(sessionId, cancellationToken);
                    return UserAccessTokenResult.Failed(UserAccessTokenFailure.RefreshTokenRejected);
                }

                return UserAccessTokenResult.Failed(UserAccessTokenFailure.ProviderUnavailable);
            }

            if (root.ValueKind != JsonValueKind.Object
                || StringProperty(root, "access_token") is not { Length: > 0 } token
                || !string.Equals(StringProperty(root, "token_type"), "Bearer", StringComparison.OrdinalIgnoreCase))
            {
                logger.RefreshAnsweredWithoutBearerToken(session.Scheme);
                return UserAccessTokenResult.Failed(UserAccessTokenFailure.ProviderUnavailable);
            }

            if (StringProperty(root, "refresh_token") is { Length: > 0 } rotated && rotated != session.RefreshToken)
            {
                await store.Update(sessionId, session with { RefreshToken = rotated }, cancellationToken);
            }

            var now = timeProvider.GetUtcNow();
            var lifetime = Lifetime(root);
            var renewAt = now + lifetime - (lifetime > RenewalMargin * 2 ? RenewalMargin : lifetime / 2);
            await store.SetAccessToken(sessionId, audience, new CachedUserAccessToken(token, now + lifetime), renewAt, cancellationToken);

            return UserAccessTokenResult.Success(token);
        }
        catch (Exception exception) when (
            exception is HttpRequestException or JsonException or OidcClientCredentialUnavailable or InvalidOperationException or IOException
            || (exception is TaskCanceledException && !cancellationToken.IsCancellationRequested))
        {
            logger.RefreshFailed(session.Scheme, exception);
            return UserAccessTokenResult.Failed(UserAccessTokenFailure.ProviderUnavailable);
        }
    }

    async Task<Dictionary<string, string>> Form(
        UserTokenSession session,
        C.OidcProvider provider,
        OpenIdConnectOptions options,
        C.ServiceAccessToken accessToken,
        string tokenEndpoint,
        CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = session.RefreshToken,
            ["client_id"] = options.ClientId!,
        };

        var scopes = string.Join(' ', accessToken.Scopes.Select(_ => _.Trim()).Where(_ => _.Length > 0));
        if (scopes.Length > 0)
        {
            form["scope"] = scopes;
        }

        if (!string.IsNullOrWhiteSpace(accessToken.Resource))
        {
            form["resource"] = accessToken.Resource.Trim();
        }

        if (provider.UsesClientAssertion)
        {
            form["client_assertion_type"] = OidcClientAuthentication.JwtBearerAssertionType;
            form["client_assertion"] = await clientAssertions.Create(session.Scheme, provider, tokenEndpoint, cancellationToken);
        }
        else if (!string.IsNullOrEmpty(options.ClientSecret))
        {
            form["client_secret"] = options.ClientSecret;
        }

        return form;
    }
}
