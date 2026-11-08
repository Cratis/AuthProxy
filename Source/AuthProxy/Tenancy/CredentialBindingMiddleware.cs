// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.ErrorPages;
using Cratis.AuthProxy.OnBehalfSessions;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Model;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>Refuses credentials bound to another tenant before membership lookup or namespace selection.</summary>
/// <param name="next">The next middleware.</param>
/// <param name="config">The deployment configuration.</param>
/// <param name="tenantResolver">The tenant resolution strategies.</param>
/// <param name="selectedTenantCookie">The account-bound tenant selection.</param>
/// <param name="errorPageProvider">The forbidden response writer.</param>
/// <param name="logger">The logger.</param>
/// <param name="checkEffectiveTenant">Whether selection has completed and the effective tenant must also be checked.</param>
public class CredentialBindingMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> config,
    ITenantResolver tenantResolver,
    SelectedTenantCookie selectedTenantCookie,
    IErrorPageProvider errorPageProvider,
    ILogger<CredentialBindingMiddleware> logger,
    bool checkEffectiveTenant = false)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        var current = config.CurrentValue;
        context.TryGetOnBehalf(out var onBehalf);
        if (!RequiresBindingCheck(context, current, onBehalf, checkEffectiveTenant))
        {
            await next(context);
            return;
        }

        var resolutions = tenantResolver.ResolveEach(context).ToArray();
        var credentials = CredentialTenants(context, onBehalf, resolutions).ToArray();
        var targets = resolutions.Where(target => CredentialTarget.IsAddressedByRequest(target.Strategy, bearerRoute: false));
        var effectiveTenantApplies = checkEffectiveTenant && onBehalf is null;
        if (effectiveTenantApplies && tenantResolver.TryResolve(context, out TenantResolutionResult effective))
        {
            targets = targets.Append(effective);
        }

        var conflicts = targets.Any(target => credentials.Any(tenant => !CredentialTarget.MatchesTenant(tenant, target.TenantId)));
        if (conflicts)
        {
            var kind = onBehalf is not null ? "on-behalf" : HasClientCredentialsIdentity(context) ? "client-credentials" : "session";
            logger.CredentialBoundToAnotherTenant(kind, RequestPathRedaction.Redact(context.Request.Path));
            context.Response.Headers.CacheControl = "no-store";
            await errorPageProvider.WriteErrorPageAsync(context, WellKnownPageNames.Forbidden, StatusCodes.Status403Forbidden);
            return;
        }

        await next(context);
    }

    static bool RequiresBindingCheck(HttpContext context, C.AuthProxy current, OnBehalfContext? onBehalf, bool checkEffectiveTenant)
    {
        var anonymous = AnonymousPaths.IsAnonymousRoute(context);
        if (current.TenantResolutions.Count == 0) return false;
        if (context.User.Identity?.IsAuthenticated != true && onBehalf is null) return false;
        if (anonymous) return false;

        // The chooser answers locally. Any request it continues still passes the second binding check.
        if (!checkEffectiveTenant
            && onBehalf is null
            && ExternalTokenTenantBinding.BoundTenant(context.User) is null
            && context.Request.Path.StartsWithSegments(WellKnownPaths.SelectTenant)
            && TenantSelectionMiddleware.TryGetSelectionOptions(current, out _)
            && !TenantSelectionExemptions.IsExemptFromTenantSelection(context, current))
        {
            return false;
        }

        if (context.GetEndpoint()?.Metadata.GetMetadata<RouteModel>() is not null) return true;
        if (context.IsProxyOwnedFlow()) return false;
        return context.GetEndpoint() is null || !TenantSelectionExemptions.IsExemptPath(context, current);
    }

    static bool HasClientCredentialsIdentity(HttpContext context) =>
        context.User.Identities.Any(identity => identity.AuthenticationType == ClientCredentialsDefaults.AuthenticationScheme);

    IEnumerable<string> CredentialTenants(HttpContext context, OnBehalfContext? onBehalf, IEnumerable<TenantResolutionResult> resolutions)
    {
        if (onBehalf is not null)
        {
            yield return onBehalf.Session.Tenant;
            yield break;
        }

        var externalTenant = ExternalTokenTenantBinding.BoundTenant(context.User);
        if (externalTenant is not null) yield return externalTenant;

        var selection = selectedTenantCookie.Read(context);
        if (selection.State == SelectedTenantCookieState.Bound) yield return selection.TenantId;
        foreach (var claim in resolutions.Where(result => result.Strategy == C.TenantSourceIdentifierResolverType.Claim)) yield return claim.TenantId;
        foreach (var identity in context.User.Identities.Where(identity => identity.AuthenticationType == ClientCredentialsDefaults.AuthenticationScheme))
        {
            foreach (var claim in identity.FindAll(ClientCredentialsDefaults.TenantClaimType)) yield return claim.Value;
        }
    }
}
