// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Net;
using System.Text.Encodings.Web;
using System.Text.Json.Nodes;
using Cratis.Arc.Identity;
using Cratis.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Calls every service's <c>/.cratis/me</c> endpoint to retrieve application-specific
/// identity details, merges the JSON results, converts them to an <see cref="IdentityProviderResult"/>
/// and stores it in the <c>.cratis-identity</c> response cookie as a base64-encoded JSON string.
/// </summary>
/// <param name="config">The auth proxy configuration.</param>
/// <param name="httpClientFactory">The HTTP client factory.</param>
/// <param name="principalEnrichers">Enrichers that augment the principal before it is sent to the identity endpoint.</param>
/// <param name="memoryCache">The memory cache used to deduplicate concurrent identity resolutions.</param>
/// <param name="logger">The logger.</param>
public class IdentityDetailsResolver(
    IOptionsMonitor<C.AuthProxy> config,
    IHttpClientFactory httpClientFactory,
    IEnumerable<IIdentityDetailsPrincipalEnricher> principalEnrichers,
    IMemoryCache memoryCache,
    ILogger<IdentityDetailsResolver> logger) : IIdentityDetailsResolver
{
    static readonly TimeSpan _cacheTtl = TimeSpan.FromSeconds(30);
    static readonly JsonSerializerOptions _cookieSerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new ConceptAsJsonConverterFactory() }
    };

    readonly ConcurrentDictionary<string, SemaphoreSlim> _resolverLocks = new();

    /// <inheritdoc/>
    public async Task<IdentityProviderResult> Resolve(HttpContext context, ClientPrincipal principal, string tenantId)
    {
        if (context.Request.Cookies.ContainsKey(Cookies.Identity))
        {
            return BuildAuthorizedResult(principal, details: null);
        }

        var cacheKey = $"{tenantId}:{principal.UserId}";

        if (memoryCache.TryGetValue(cacheKey, out IdentityProviderResult? cached) && cached is not null)
        {
            WriteIdentityCookie(context, cached);
            logger.IdentityDetailsCacheHit(principal.UserId);
            return cached;
        }

        var semaphore = _resolverLocks.GetOrAdd(cacheKey, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync();
        try
        {
            // Double-check inside the lock — another request may have populated the cache while we waited.
            if (memoryCache.TryGetValue(cacheKey, out cached) && cached is not null)
            {
                WriteIdentityCookie(context, cached);
                logger.IdentityDetailsCacheHit(principal.UserId);
                return cached;
            }

            var enrichedPrincipal = principalEnrichers.Aggregate(principal, (p, enricher) => enricher.Enrich(context, p));
            var mergedDetails = new JsonObject();
            var services = config.CurrentValue.Services;

            foreach (var (name, service) in services)
            {
                var shouldResolve = service.ResolveIdentityDetails ?? (service.Backend is not null);
                if (!shouldResolve || service.Backend is null)
                {
                    continue;
                }

                logger.CallingIdentityEndpointWithPrincipal(name, enrichedPrincipal.UserId);

                var result = await CallIdentityEndpoint(
                    name,
                    service.Backend.BaseUrl,
                    enrichedPrincipal,
                    tenantId,
                    context.Response);

                if (result is null)
                {
                    return IdentityProviderResult.Unauthorized;
                }

                foreach (var property in result)
                {
                    mergedDetails[property.Key] = property.Value?.DeepClone();
                }
            }

            var identityResult = BuildAuthorizedResult(principal, mergedDetails.Count > 0 ? mergedDetails : null);
            WriteIdentityCookie(context, identityResult);
            logger.IdentityDetailsCookieWritten(principal.UserId);
            memoryCache.Set(cacheKey, identityResult, _cacheTtl);
            return identityResult;
        }
        finally
        {
            semaphore.Release();
        }
    }

    IdentityProviderResult BuildAuthorizedResult(ClientPrincipal principal, object? details) =>
        new(
            principal.UserId,
            principal.UserDetails,
            IsAuthenticated: true,
            IsAuthorized: true,
            principal.UserRoles,
            details!);

    void WriteIdentityCookie(HttpContext context, IdentityProviderResult result)
    {
        var json = JsonSerializer.Serialize(result, _cookieSerializerOptions);
        var encoded = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(json));

        context.Response.Cookies.Append(Cookies.Identity, encoded, new CookieOptions
        {
            HttpOnly = false,   // Must be readable by the frontend JS.
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
            Expires = null,     // Session cookie.
        });
    }

    async Task<JsonObject?> CallIdentityEndpoint(
        string serviceName,
        string baseUrl,
        ClientPrincipal principal,
        string tenantId,
        HttpResponse response)
    {
        var url = baseUrl.TrimEnd('/') + WellKnownPaths.IdentityDetails;
        logger.CallingIdentityEndpoint(url, serviceName);

        using var client = httpClientFactory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.SetMicrosoftIdentityHeaders(principal);
        request.Headers.Add(Headers.TenantId, tenantId);

        HttpResponseMessage httpResponse;
        try
        {
            httpResponse = await client.SendAsync(request);
        }
        catch (Exception ex)
        {
            logger.ErrorCallingIdentityEndpoint(ex, serviceName);
            return new JsonObject();    // Non-fatal – continue without details.
        }

        if (httpResponse.StatusCode == HttpStatusCode.Forbidden)
        {
            logger.IdentityEndpointForbidden(serviceName, principal.UserId);
            response.StatusCode = StatusCodes.Status403Forbidden;
            return null;
        }

        if (!httpResponse.IsSuccessStatusCode)
        {
            var errorBody = await httpResponse.Content.ReadAsStringAsync();
            logger.IdentityEndpointUnsuccessful(serviceName, (int)httpResponse.StatusCode, errorBody);
            return new JsonObject();
        }

        var body = await httpResponse.Content.ReadAsStringAsync();
        if (string.IsNullOrWhiteSpace(body))
        {
            return new JsonObject();
        }

        try
        {
            var parsed = JsonNode.Parse(body)?.AsObject() ?? new JsonObject();
            return parsed["details"]?.AsObject() ?? parsed;
        }
        catch (Exception ex)
        {
            logger.CouldNotParseIdentityResponse(ex, serviceName);
            return new JsonObject();
        }
    }
}
