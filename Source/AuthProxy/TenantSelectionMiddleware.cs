// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.ErrorPages;
using Cratis.AuthProxy.Identity;
using Cratis.AuthProxy.OnBehalfSessions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// Middleware that handles tenant selection for authenticated users when the selection strategy is configured.
/// A selected tenant is forwarded only after it has been confirmed for the signed-in account: the selection
/// cookie is bound to that account, and the confirmation is repeated against the tenant endpoint at the
/// interval set by <see cref="C.Session.TenantRevalidationInterval"/>. When the tenant endpoint cannot answer,
/// the request is not forwarded with that tenant. A session without a forwardable identity is terminated
/// rather than reported as an endpoint outage.
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="tenantResolver">The tenant resolver.</param>
/// <param name="httpClientFactory">The HTTP client factory.</param>
/// <param name="errorPageProvider">The error page provider used to serve the selection and service-unavailable pages.</param>
/// <param name="memoryCache">The memory cache used to bound how often the selected tenant is re-validated.</param>
/// <param name="selectedTenantCookie">The selected-tenant cookie, bound to the signed-in account.</param>
/// <param name="logger">The logger.</param>
public class TenantSelectionMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> config,
    ITenantResolver tenantResolver,
    IHttpClientFactory httpClientFactory,
    IErrorPageProvider errorPageProvider,
    IMemoryCache memoryCache,
    Tenancy.SelectedTenantCookie selectedTenantCookie,
    ILogger<TenantSelectionMiddleware> logger)
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

            // An on-behalf session acts in the one tenant its grant was confirmed for. Offering the actor a choice
            // would be offering them the represented user's other tenants, which nobody granted.
            || context.TryGetOnBehalf(out _))
        {
            await next(context);
            return;
        }

        if (!TryGetSelectionOptions(config.CurrentValue, out var selectionOptions))
        {
            await next(context);
            return;
        }

        var exempt = IsExemptFromTenantSelection(context);
        if (!exempt && context.Request.Path.StartsWithSegments(WellKnownPaths.SelectTenant))
        {
            await HandleTenantSelection(context, selectionOptions);
            return;
        }

        // A selected tenant is confirmed for the signed-in account on every request, including the paths that
        // are otherwise served without tenant selection.
        if (await ConfirmSelectedTenant(context, selectionOptions, exempt))
        {
            return;
        }

        if (exempt || tenantResolver.TryResolve(context, out TenantResolutionResult _))
        {
            await next(context);
            return;
        }

        var tenantOptionsResult = await GetTenantOptions(context, selectionOptions);
        if (!tenantOptionsResult.HasIdentity)
        {
            await HandleInvalidSession(context);
            return;
        }

        if (!tenantOptionsResult.Succeeded)
        {
            context.Response.Headers.CacheControl = "no-store";
            if (context.IsDocumentNavigation())
            {
                await errorPageProvider.WriteErrorPageAsync(
                    context,
                    WellKnownPageNames.ServiceUnavailable,
                    StatusCodes.Status503ServiceUnavailable);
                return;
            }

            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return;
        }

        var tenantOptions = tenantOptionsResult.Tenants;
        if (tenantOptions.Count == 0)
        {
            await next(context);
            return;
        }

        if (tenantOptions.Count == 1)
        {
            if (!selectedTenantCookie.TryWrite(context, tenantOptions[0].Id))
            {
                await HandleInvalidSession(context);
                return;
            }

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
        if (!Tenancy.TenantIdentifier.IsUsable(tenantId))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var tenantOptionsResult = await GetTenantOptions(context, selectionOptions);
        if (!tenantOptionsResult.HasIdentity)
        {
            await HandleInvalidSession(context);
            return;
        }

        if (!tenantOptionsResult.Succeeded)
        {
            context.Response.Headers.CacheControl = "no-store";
            await errorPageProvider.WriteErrorPageAsync(
                context,
                WellKnownPageNames.ServiceUnavailable,
                StatusCodes.Status503ServiceUnavailable);
            return;
        }

        var tenantOptions = tenantOptionsResult.Tenants;
        if (!tenantOptions.Any(_ => string.Equals(_.Id, tenantId, StringComparison.OrdinalIgnoreCase)))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        if (!selectedTenantCookie.TryWrite(context, tenantId))
        {
            await HandleInvalidSession(context);
            return;
        }

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

    async Task HandleInvalidSession(HttpContext context)
    {
        logger.TerminatingUnforwardableSession(RequestPathRedaction.Redact(context.Request.Path));
        await SessionTermination.SignOutAndClearCookies(context, config.CurrentValue.Session, config.CurrentValue.Logout);

        if (context.IsDocumentNavigation())
        {
            var returnUrl = RelativeRedirect.Resolve(context.GetPathAndQuery());
            context.Response.Redirect(
                $"{WellKnownPaths.LoginPage}?{SignInFailureReason.QueryKey}={SignInFailureReason.InvalidSession}&returnUrl={Uri.EscapeDataString(returnUrl)}");
            return;
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
    }

    /// <summary>
    /// Determines whether the request is served without tenant selection: invitations, registrations,
    /// authentication bootstrap, declared anonymous paths and pending invitation or registration sessions.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns><see langword="true"/> when no tenant is chosen for the request; otherwise <see langword="false"/>.</returns>
    bool IsExemptFromTenantSelection(HttpContext context) =>
        context.IsInvitation()
        || context.IsRegistration()
        || context.IsAuthenticationBootstrap()

        // A path the deployment declares anonymous is served without regard to who is asking, so it
        // stays reachable for a caller who happens to be signed in without having chosen a tenant.
        || context.IsAnonymousPath(config.CurrentValue)
        || context.HasPendingInvitation()
        || context.HasPendingRegistration();

    /// <summary>
    /// Confirms the tenant named by the selected-tenant cookie for the signed-in account and records it on the request.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="selectionOptions">The selection strategy options carrying the tenant endpoint.</param>
    /// <param name="exempt">Whether the request is served without tenant selection.</param>
    /// <returns><see langword="true"/> when a response was written and the request ends here; otherwise <see langword="false"/>.</returns>
    async Task<bool> ConfirmSelectedTenant(HttpContext context, Tenancy.SelectionOptions selectionOptions, bool exempt)
    {
        var cookie = selectedTenantCookie.Read(context);
        if (cookie.State == Tenancy.SelectedTenantCookieState.None)
        {
            return false;
        }

        if (cookie.State == Tenancy.SelectedTenantCookieState.Invalid)
        {
            logger.SelectedTenantCookieRejected();
            Tenancy.SelectedTenantCookie.Delete(context);
            return false;
        }

        var tenantId = cookie.TenantId;
        var principal = context.BuildClientPrincipal();
        var hasBinding = IdentityAccountBinding.TryCreate(principal ?? new(), out var account);
        var cached = hasBinding && memoryCache.TryGetValue(RevalidationCacheKey(account, tenantId), out _);
        var legacy = cookie.State == Tenancy.SelectedTenantCookieState.Legacy;
        var interval = config.CurrentValue.Session.TenantRevalidationInterval;

        if (cached || (!legacy && interval <= TimeSpan.Zero))
        {
            Confirm(context, tenantId, legacy);
            return false;
        }

        var result = await GetTenantOptions(context, selectionOptions);
        if (!result.HasIdentity)
        {
            if (exempt)
            {
                return false;
            }

            await HandleInvalidSession(context);
            return true;
        }

        if (!result.Succeeded)
        {
            logger.SelectedTenantNotConfirmed();
            return !exempt && await RejectUnconfirmed(context);
        }

        if (!result.Tenants.Any(_ => string.Equals(_.Id, tenantId, StringComparison.OrdinalIgnoreCase)))
        {
            // The user is no longer entitled to the selected tenant. Drop the stale tenant context and
            // replay the request without it so the regular selection flow takes over.
            Tenancy.SelectedTenantCookie.Delete(context);
            context.Response.Cookies.Delete(Cookies.Tenants);
            if (exempt)
            {
                return false;
            }

            context.Response.StatusCode = StatusCodes.Status302Found;
            context.Response.Headers.Location = context.GetPathAndQuery();
            return true;
        }

        MarkTenantAsRevalidated(context, tenantId);
        Confirm(context, tenantId, legacy);
        return false;
    }

    async Task<bool> RejectUnconfirmed(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (context.IsDocumentNavigation())
        {
            await errorPageProvider.WriteErrorPageAsync(
                context,
                WellKnownPageNames.ServiceUnavailable,
                StatusCodes.Status503ServiceUnavailable);
            return true;
        }

        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        return true;
    }

    void Confirm(HttpContext context, string tenantId, bool reissue)
    {
        context.Items[Tenancy.SelectionSourceIdentifierStrategy.ConfirmedTenantItemKey] = tenantId;
        if (reissue)
        {
            selectedTenantCookie.TryWrite(context, tenantId);
        }
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

    /// <summary>
    /// Fetches an authoritative tenant list, distinguishing no tenant access from an unavailable endpoint.
    /// Unavailability is surfaced as HTTP 503 during selection, but fails open during cookie re-validation.
    /// A missing forwardable identity is a separate outcome that terminates the session during selection.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="selectionOptions">The selection strategy options carrying the tenant endpoint.</param>
    /// <returns>The tenant list and whether the endpoint gave an authoritative answer.</returns>
    async Task<TenantOptionsResult> GetTenantOptions(HttpContext context, Tenancy.SelectionOptions selectionOptions)
    {
        var principal = context.BuildClientPrincipal();
        if (principal is null)
        {
            return TenantOptionsResult.NoIdentity;
        }

        using var client = httpClientFactory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, selectionOptions.TenantsEndpoint);
        request.SetMicrosoftIdentityHeaders(principal);

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request);
        }
        catch (Exception exception)
        {
            logger.TenantEndpointUnavailable(exception.GetType().Name);
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
            logger.TenantEndpointReturnedError((int)response.StatusCode);
            return TenantOptionsResult.Unavailable;
        }

        try
        {
            var json = await response.Content.ReadAsStringAsync();
            if (string.IsNullOrWhiteSpace(json))
            {
                return new(Succeeded: true, []);
            }

            var tenants = JsonSerializer.Deserialize<List<TenantOption>>(json, _serializerOptions) ?? [];
            return new(
                Succeeded: true,
                tenants
                    .Where(_ => Tenancy.TenantIdentifier.IsUsable(_.Id) && !string.IsNullOrWhiteSpace(_.Name))
                    .DistinctBy(_ => _.Id, StringComparer.OrdinalIgnoreCase)
                    .ToList());
        }
        catch (Exception exception)
        {
            logger.TenantEndpointReturnedUnusableResponse(exception.GetType().Name);
            return TenantOptionsResult.Unavailable;
        }
    }

    sealed record TenantOption(
        [property: System.Text.Json.Serialization.JsonPropertyName("id")] string Id,
        [property: System.Text.Json.Serialization.JsonPropertyName("name")] string Name);

    /// <summary>
    /// The outcome of calling the tenant endpoint. <c language="text">Succeeded</c> is <see langword="false"/> when
    /// the endpoint could not give an authoritative answer (unreachable, server error, unparseable body)
    /// or no forwardable identity exists; <c language="text">HasIdentity</c> distinguishes the session failure.
    /// an authoritative "no tenants" answer has <c language="text">Succeeded</c> <see langword="true"/> with an empty list.
    /// An unavailable result produces HTTP 503 during selection, but permits an already selected tenant
    /// to continue during re-validation.
    /// </summary>
    /// <param name="Succeeded">Whether the endpoint gave an authoritative answer.</param>
    /// <param name="Tenants">The tenants available to the user when the call succeeded.</param>
    /// <param name="HasIdentity">Whether the session has a forwardable identity.</param>
    sealed record TenantOptionsResult(bool Succeeded, IReadOnlyList<TenantOption> Tenants, bool HasIdentity = true)
    {
        public static readonly TenantOptionsResult Unavailable = new(false, []);
        public static readonly TenantOptionsResult NoIdentity = new(false, [], HasIdentity: false);
    }
}
