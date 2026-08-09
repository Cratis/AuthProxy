// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;
using Cratis.AuthProxy.Identity;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// Middleware that handles tenant selection for authenticated users when the selection strategy is configured.
/// A tenant resolved from the selection cookie is periodically re-validated against the tenant endpoint
/// (bounded by <see cref="C.Session.TenantRevalidationInterval"/>) so revoked tenant access takes effect
/// without calling the backend on every request.
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="tenantResolver">The tenant resolver.</param>
/// <param name="httpClientFactory">The HTTP client factory.</param>
/// <param name="errorPageProvider">The error page provider used to serve the selection page.</param>
/// <param name="memoryCache">The memory cache used to bound how often the selected tenant is re-validated.</param>
public class TenantSelectionMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> config,
    ITenantResolver tenantResolver,
    IHttpClientFactory httpClientFactory,
    IErrorPageProvider errorPageProvider,
    IMemoryCache memoryCache)
{
    const string RevalidationCacheKeyPrefix = "TenantSelectionRevalidation";

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

            // A path the deployment declares anonymous is served without regard to who is asking, so it
            // stays reachable for a caller who happens to be signed in without having chosen a tenant.
            // Without this, declaring a path anonymous only opens it to callers with no session at all.
            || context.IsAnonymousPath(config.CurrentValue)
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

        if (tenantResolver.TryResolve(context, out TenantResolutionResult resolution))
        {
            if (await IsResolvedTenantStillValid(context, selectionOptions, resolution))
            {
                await next(context);
                return;
            }

            // The user is no longer entitled to the selected tenant. Drop the stale tenant context and
            // replay the request without it so the regular selection flow (or the no-tenant machinery
            // further down the pipeline) takes over.
            context.Response.Cookies.Delete(Cookies.Tenant);
            context.Response.Cookies.Delete(Cookies.Tenants);
            context.Response.StatusCode = StatusCodes.Status302Found;
            context.Response.Headers.Location = context.GetPathAndQuery();
            return;
        }

        var tenantOptions = (await GetTenantOptions(context, selectionOptions)).Tenants;
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
            MarkTenantAsRevalidated(context, tenantOptions[0].Id);
            context.Response.StatusCode = StatusCodes.Status302Found;
            context.Response.Headers.Location = context.GetPathAndQuery();
            return;
        }

        // The chooser is a page, and a page can only be delivered with a success status. To a caller that
        // is not navigating that reads as the data it asked for, arriving intact — the same silent success
        // the provider-selection page produces, reached here by an already-signed-in frontend. It is
        // refused with 403 rather than 401 because the caller is authenticated: a 401 would send a
        // frontend back through a login it has already completed.
        if (!context.IsDocumentNavigation())
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        // Written as a session cookie so that, once a multi-tenant user has selected a tenant, the
        // tenant list remains available to the application's toolbar switcher for the rest of the
        // browser session. It is intentionally not deleted on selection.
        var tenantsJson = JsonSerializer.Serialize(tenantOptions, _serializerOptions);
        context.Response.Cookies.Append(Cookies.Tenants, tenantsJson, new CookieOptions
        {
            HttpOnly = false,
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
        });

        await errorPageProvider.WriteErrorPageAsync(
            context,
            WellKnownPageNames.SelectTenant,
            StatusCodes.Status200OK);
    }

    static IdentityAccountTenantKey RevalidationCacheKey(IdentityAccountBinding account, string tenantId) =>
        IdentityAccountTenantKey.Create(RevalidationCacheKeyPrefix, account, tenantId);

    async Task HandleTenantSelection(HttpContext context, Tenancy.SelectionOptions selectionOptions)
    {
        var tenantId = context.Request.Query["tenantId"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var tenantOptions = (await GetTenantOptions(context, selectionOptions)).Tenants;
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
        MarkTenantAsRevalidated(context, tenantId);

        // The tenant list is intentionally retained (not deleted) so a multi-tenant user keeps the
        // ability to switch tenants from the application's toolbar after making a selection.
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

    /// <summary>
    /// Determines whether a resolved tenant may still be honored. Only tenants resolved from the
    /// selection cookie are subject to re-validation — every other strategy derives the tenant from
    /// the request itself. A successful re-validation is cached for the configured interval so the
    /// tenant endpoint is not called on every request; when the endpoint answers authoritatively that
    /// the tenant is no longer available to the user the selection is considered revoked. Transport
    /// failures fail open so a transient backend outage cannot lock every user out.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="selectionOptions">The selection strategy options carrying the tenant endpoint.</param>
    /// <param name="resolution">The tenant resolution outcome for the request.</param>
    /// <returns><see langword="true"/> when the resolved tenant may be honored; otherwise <see langword="false"/>.</returns>
    async Task<bool> IsResolvedTenantStillValid(HttpContext context, Tenancy.SelectionOptions selectionOptions, TenantResolutionResult resolution)
    {
        if (resolution.Strategy != C.TenantSourceIdentifierResolverType.Selection)
        {
            return true;
        }

        var interval = config.CurrentValue.Session.TenantRevalidationInterval;
        if (interval <= TimeSpan.Zero)
        {
            return true;
        }

        var principal = context.BuildClientPrincipal();
        if (principal is null)
        {
            return true;
        }

        var hasReusableBinding = IdentityAccountBinding.TryCreate(principal, out var account);
        if (hasReusableBinding && memoryCache.TryGetValue(RevalidationCacheKey(account, resolution.TenantId), out _))
        {
            return true;
        }

        var tenantOptions = await GetTenantOptions(context, selectionOptions);
        if (!tenantOptions.Succeeded)
        {
            return true;
        }

        if (!tenantOptions.Tenants.Any(_ => string.Equals(_.Id, resolution.TenantId, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        MarkTenantAsRevalidated(context, resolution.TenantId);
        return true;
    }

    /// <summary>
    /// Records that the given tenant has just been confirmed against the tenant endpoint for the current
    /// user, starting a fresh re-validation window.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/> whose user the confirmation applies to.</param>
    /// <param name="tenantId">The tenant that was confirmed.</param>
    void MarkTenantAsRevalidated(HttpContext context, string tenantId)
    {
        var interval = config.CurrentValue.Session.TenantRevalidationInterval;
        if (interval <= TimeSpan.Zero)
        {
            return;
        }

        var principal = context.BuildClientPrincipal();
        if (principal is null || !IdentityAccountBinding.TryCreate(principal, out var account))
        {
            return;
        }

        memoryCache.Set(RevalidationCacheKey(account, tenantId), true, interval);
    }

    bool IsSafeRelativeUrl(string? url) => RelativeRedirect.IsSameSiteRelative(url);

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

    async Task<TenantOptionsResult> GetTenantOptions(HttpContext context, Tenancy.SelectionOptions selectionOptions)
    {
        var principal = context.BuildClientPrincipal();
        if (principal is null)
        {
            return TenantOptionsResult.Unavailable;
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
            return TenantOptionsResult.Unavailable;
        }

        if (response.StatusCode == System.Net.HttpStatusCode.Forbidden || response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            // An authoritative answer: the user is not entitled to any tenant at all. Reporting it as an
            // empty-but-successful result forwards the request, and TenancyMiddleware — which finds no
            // tenant to resolve for an authenticated user — answers it with the no-organization page at
            // 403. Setting a status here would only be overwritten by that, and a 403 naming the actual
            // reason is the better answer anyway.
            return new(Succeeded: true, []);
        }

        if (!response.IsSuccessStatusCode)
        {
            return TenantOptionsResult.Unavailable;
        }

        var json = await response.Content.ReadAsStringAsync();
        if (string.IsNullOrWhiteSpace(json))
        {
            return new(Succeeded: true, []);
        }

        try
        {
            var tenants = JsonSerializer.Deserialize<List<TenantOption>>(json, _serializerOptions) ?? [];
            return new(
                Succeeded: true,
                tenants
                    .Where(_ => !string.IsNullOrWhiteSpace(_.Id) && !string.IsNullOrWhiteSpace(_.Name))
                    .DistinctBy(_ => _.Id, StringComparer.OrdinalIgnoreCase)
                    .ToList());
        }
        catch (Exception)
        {
            return TenantOptionsResult.Unavailable;
        }
    }

    sealed record TenantOption(
        [property: System.Text.Json.Serialization.JsonPropertyName("id")] string Id,
        [property: System.Text.Json.Serialization.JsonPropertyName("name")] string Name);

    /// <summary>
    /// The outcome of calling the tenant endpoint. <c>Succeeded</c> is <see langword="false"/> only when
    /// the endpoint could not give an authoritative answer (unreachable, server error, unparseable body);
    /// an authoritative "no tenants" answer has <c>Succeeded</c> <see langword="true"/> with an empty list.
    /// </summary>
    /// <param name="Succeeded">Whether the endpoint gave an authoritative answer.</param>
    /// <param name="Tenants">The tenants available to the user when the call succeeded.</param>
    sealed record TenantOptionsResult(bool Succeeded, IReadOnlyList<TenantOption> Tenants)
    {
        public static readonly TenantOptionsResult Unavailable = new(false, []);
    }
}
