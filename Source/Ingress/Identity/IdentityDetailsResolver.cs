// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text.Json.Nodes;
using Cratis.Ingress.Configuration;
using Microsoft.Extensions.Options;

namespace Cratis.Ingress.Identity;

/// <summary>
/// Calls every microservice's <c>/.cratis/me</c> endpoint to retrieve application-specific
/// identity details, merges the JSON results and stores them in the <c>.cratis-identity</c>
/// response cookie as a base64-encoded JSON string.
/// </summary>
/// <param name="config">The ingress configuration.</param>
/// <param name="httpClientFactory">The HTTP client factory.</param>
/// <param name="logger">The logger.</param>
public class IdentityDetailsResolver(
    IOptionsMonitor<IngressConfig> config,
    IHttpClientFactory httpClientFactory,
    ILogger<IdentityDetailsResolver> logger) : IIdentityDetailsResolver
{
    /// <inheritdoc/>
    public async Task<bool> Resolve(HttpContext context, ClientPrincipal principal, Guid tenantId)
    {
        // Skip when the identity cookie is already present for this request.
        if (context.Request.Cookies.ContainsKey(Cookies.Identity))
        {
            return true;
        }

        var mergedDetails = new JsonObject();
        var microservices = config.CurrentValue.Microservices;

        foreach (var (name, microservice) in microservices)
        {
            var shouldResolve = microservice.ResolveIdentityDetails
                ?? (microservice.Backend is not null);

            if (!shouldResolve || microservice.Backend is null)
            {
                continue;
            }

            var result = await CallIdentityEndpoint(
                name,
                microservice.Backend.BaseUrl,
                principal,
                tenantId,
                context.Response);

            if (result is null)
            {
                // 403 – stop processing.
                return false;
            }

            // Merge top-level properties from this microservice into the combined result.
            foreach (var property in result)
            {
                mergedDetails[property.Key] = property.Value?.DeepClone();
            }
        }

        if (mergedDetails.Count > 0)
        {
            var json = mergedDetails.ToJsonString();
            var encoded = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(json));
            context.Response.Cookies.Append(Cookies.Identity, encoded, new CookieOptions
            {
                HttpOnly = false,   // Must be readable by the frontend JS.
                SameSite = SameSiteMode.Lax,
                Secure = context.Request.IsHttps,
                Expires = null,     // Session cookie.
            });

            logger.IdentityDetailsCookieWritten(principal.UserId);
        }

        return true;
    }

    async Task<JsonObject?> CallIdentityEndpoint(
        string microserviceName,
        string baseUrl,
        ClientPrincipal principal,
        Guid tenantId,
        HttpResponse response)
    {
        var url = baseUrl.TrimEnd('/') + WellKnownPaths.IdentityDetails;
        logger.CallingIdentityEndpoint(url, microserviceName);

        using var client = httpClientFactory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.SetMicrosoftIdentityHeaders(principal);
        request.Headers.Add(Headers.TenantId, tenantId.ToString());

        HttpResponseMessage httpResponse;
        try
        {
            httpResponse = await client.SendAsync(request);
        }
        catch (Exception ex)
        {
            logger.ErrorCallingIdentityEndpoint(ex, microserviceName);
            return new JsonObject();    // Non-fatal – continue without details.
        }

        if (httpResponse.StatusCode == HttpStatusCode.Forbidden)
        {
            logger.IdentityEndpointForbidden(microserviceName, principal.UserId);
            response.StatusCode = StatusCodes.Status403Forbidden;
            return null;
        }

        if (!httpResponse.IsSuccessStatusCode)
        {
            logger.IdentityEndpointUnsuccessful(microserviceName, (int)httpResponse.StatusCode);
            return new JsonObject();
        }

        var body = await httpResponse.Content.ReadAsStringAsync();
        if (string.IsNullOrWhiteSpace(body))
        {
            return new JsonObject();
        }

        try
        {
            return JsonNode.Parse(body)?.AsObject() ?? new JsonObject();
        }
        catch (Exception ex)
        {
            logger.CouldNotParseIdentityResponse(ex, microserviceName);
            return new JsonObject();
        }
    }
}
