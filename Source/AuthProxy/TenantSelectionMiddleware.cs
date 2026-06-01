// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;
using Cratis.AuthProxy.Identity;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// Middleware that handles tenant selection for authenticated users when the selection strategy is configured.
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="tenantResolver">The tenant resolver.</param>
/// <param name="httpClientFactory">The HTTP client factory.</param>
/// <param name="errorPageProvider">The error page provider used to serve the selection page.</param>
public class TenantSelectionMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> config,
    ITenantResolver tenantResolver,
    IHttpClientFactory httpClientFactory,
    IErrorPageProvider errorPageProvider)
{
    static readonly JsonSerializerOptions _serializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.User.Identity?.IsAuthenticated != true
            || context.IsInvitation()
            || context.IsRegistration()
            || context.IsAuthenticationBootstrap()
            || context.HasPendingInvitation()
            || context.HasPendingRegistration())
        {
            await next(context);
            return;
        }

        if (!TryGetSelectionOptions(config.CurrentValue, out var selectionOptions))
        {
            await next(context);
            return;
        }

        if (context.Request.Path.StartsWithSegments(WellKnownPaths.SelectTenant))
        {
            await HandleTenantSelection(context, selectionOptions);
            return;
        }

        if (tenantResolver.TryResolve(context, out string _))
        {
            await next(context);
            return;
        }

        var tenantOptions = await GetTenantOptions(context, selectionOptions);
        if (tenantOptions.Count == 0)
        {
            await next(context);
            return;
        }

        if (tenantOptions.Count == 1)
        {
            context.Response.Cookies.Append(Cookies.Tenant, tenantOptions[0].Id, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax,
                Secure = context.Request.IsHttps,
            });
            context.Response.Cookies.Delete(Cookies.Tenants);
            context.Response.StatusCode = StatusCodes.Status302Found;
            context.Response.Headers.Location = context.GetPathAndQuery();
            return;
        }

        var tenantsJson = JsonSerializer.Serialize(tenantOptions, _serializerOptions);
        context.Response.Cookies.Append(Cookies.Tenants, tenantsJson, new CookieOptions
        {
            HttpOnly = false,
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
            MaxAge = TimeSpan.FromMinutes(15),
        });

        await errorPageProvider.WriteErrorPageAsync(
            context,
            WellKnownPageNames.SelectTenant,
            StatusCodes.Status200OK);
    }

    async Task HandleTenantSelection(HttpContext context, Tenancy.SelectionOptions selectionOptions)
    {
        var tenantId = context.Request.Query["tenantId"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var tenantOptions = await GetTenantOptions(context, selectionOptions);
        if (!tenantOptions.Any(_ => string.Equals(_.Id, tenantId, StringComparison.OrdinalIgnoreCase)))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        context.Response.Cookies.Append(Cookies.Tenant, tenantId, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
        });

        context.Response.Cookies.Delete(Cookies.Tenants);

        var requestedReturnUrl = context.Request.Query["returnUrl"].FirstOrDefault();
        if (!IsSafeRelativeUrl(requestedReturnUrl))
        {
            context.Response.StatusCode = StatusCodes.Status302Found;
            context.Response.Headers.Location = "/";
            return;
        }

        context.Response.StatusCode = StatusCodes.Status302Found;
        context.Response.Headers.Location = requestedReturnUrl;
    }

    bool IsSafeRelativeUrl(string? url) =>
        !string.IsNullOrWhiteSpace(url)
        && Uri.TryCreate(url, UriKind.Relative, out _)
        && url.StartsWith('/');

    bool TryGetSelectionOptions(C.AuthProxy authProxyConfig, out Tenancy.SelectionOptions selectionOptions)
    {
        selectionOptions = new();
        var selectionResolution = authProxyConfig.TenantResolutions
            .FirstOrDefault(_ => _.Strategy == C.TenantSourceIdentifierResolverType.Selection);
        if (selectionResolution?.Options is not Tenancy.SelectionOptions typedSelectionOptions)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(typedSelectionOptions.TenantsEndpoint)
            || !Uri.IsWellFormedUriString(typedSelectionOptions.TenantsEndpoint, UriKind.Absolute))
        {
            return false;
        }

        selectionOptions = typedSelectionOptions;
        return true;
    }

    async Task<IReadOnlyList<TenantOption>> GetTenantOptions(HttpContext context, Tenancy.SelectionOptions selectionOptions)
    {
        var principal = context.BuildClientPrincipal();
        if (principal is null)
        {
            return [];
        }

        using var client = httpClientFactory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, selectionOptions.TenantsEndpoint);
        request.SetMicrosoftIdentityHeaders(principal);

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request);
        }
        catch (Exception)
        {
            return [];
        }

        if (response.StatusCode == System.Net.HttpStatusCode.Forbidden || response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return [];
        }

        if (!response.IsSuccessStatusCode)
        {
            return [];
        }

        var json = await response.Content.ReadAsStringAsync();
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            var tenants = JsonSerializer.Deserialize<List<TenantOption>>(json, _serializerOptions) ?? [];
            return tenants
                .Where(_ => !string.IsNullOrWhiteSpace(_.Id) && !string.IsNullOrWhiteSpace(_.Name))
                .DistinctBy(_ => _.Id, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception)
        {
            return [];
        }
    }

    sealed record TenantOption(
        [property: System.Text.Json.Serialization.JsonPropertyName("id")] string Id,
        [property: System.Text.Json.Serialization.JsonPropertyName("name")] string Name);
}
