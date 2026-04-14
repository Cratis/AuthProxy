// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text.Encodings.Web;
using System.Text.Json.Nodes;
using Cratis.Arc.Identity;
using Cratis.Ingress.Configuration;
using Cratis.Ingress.Invites;
using Cratis.Json;
using Microsoft.Extensions.Options;

namespace Cratis.Ingress.Identity;

/// <summary>
/// Calls every microservice's <c>/.cratis/me</c> endpoint to retrieve application-specific
/// identity details, merges the JSON results, converts them to an <see cref="IdentityProviderResult"/>
/// and stores it in the <c>.cratis-identity</c> response cookie as a base64-encoded JSON string.
/// </summary>
/// <param name="config">The ingress configuration.</param>
/// <param name="httpClientFactory">The HTTP client factory.</param>
/// <param name="inviteTokenValidator">The invite token validator.</param>
/// <param name="logger">The logger.</param>
public class IdentityDetailsResolver(
    IOptionsMonitor<IngressConfig> config,
    IHttpClientFactory httpClientFactory,
    IInviteTokenValidator inviteTokenValidator,
    ILogger<IdentityDetailsResolver> logger) : IIdentityDetailsResolver
{
    static readonly JsonSerializerOptions _cookieSerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new ConceptAsJsonConverterFactory() }
    };

    /// <inheritdoc/>
    public async Task<IdentityProviderResult> Resolve(HttpContext context, ClientPrincipal principal, Guid tenantId)
    {
        var hasPendingInviteToken = context.Request.Cookies.ContainsKey(Cookies.InviteToken);

        // Skip only when identity is already present and we are not in an invite flow.
        if (context.Request.Cookies.ContainsKey(Cookies.Identity) && !hasPendingInviteToken)
        {
            return BuildAuthorizedResult(principal, details: null);
        }

        var principalForIdentityResolution = CreatePrincipalForIdentityResolution(context, principal);

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
                principalForIdentityResolution,
                tenantId,
                context.Response);

            if (result is null)
            {
                // 403 – stop processing.
                return IdentityProviderResult.Unauthorized;
            }

            // Merge top-level properties from this microservice into the combined result.
            foreach (var property in result)
            {
                mergedDetails[property.Key] = property.Value?.DeepClone();
            }
        }

        var identityResult = BuildAuthorizedResult(principal, mergedDetails.Count > 0 ? mergedDetails : null);
        WriteIdentityCookie(context, identityResult);
        logger.IdentityDetailsCookieWritten(principal.UserId);

        return identityResult;
    }

    ClientPrincipal CreatePrincipalForIdentityResolution(HttpContext context, ClientPrincipal principal)
    {
        if (!context.Request.Cookies.TryGetValue(Cookies.InviteToken, out var inviteToken)
            || string.IsNullOrWhiteSpace(inviteToken))
        {
            return principal;
        }

        if (!inviteTokenValidator.TryGetClaim(inviteToken, "jti", out var invitationId)
            || string.IsNullOrWhiteSpace(invitationId))
        {
            return principal;
        }

        return new ClientPrincipal
        {
            IdentityProvider = principal.IdentityProvider,
            UserId = invitationId,
            UserDetails = principal.UserDetails,
            UserRoles = principal.UserRoles,
            Claims = principal.Claims,
        };
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

