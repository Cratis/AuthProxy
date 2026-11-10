// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Encapsulates tenant resolution metadata that is round-tripped through authentication state.
/// </summary>
public static class TenantAuthenticationState
{
    /// <summary>Authentication state key for the tenant ID.</summary>
    public const string TenantIdStateKey = "Cratis.AuthProxy.TenantId";

    /// <summary>Authentication state key for the tenant resolution strategy.</summary>
    public const string StrategyStateKey = "Cratis.AuthProxy.TenantStrategy";

    /// <summary>Authentication state key for the SubHost parent host.</summary>
    public const string SubHostParentHostStateKey = "Cratis.AuthProxy.SubHostParentHost";

    /// <summary>
    /// Creates challenge properties and, when a tenant can be resolved, stores tenant metadata in state.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="tenantResolver">The tenant resolver used to capture tenant metadata.</param>
    /// <param name="returnUrl">The return URL to use after successful authentication.</param>
    /// <returns>An <see cref="AuthenticationProperties"/> initialized for the challenge.</returns>
    /// <remarks>
    /// The return URL is reduced to a same-site relative path. Use the overload taking the configuration where a
    /// sign-in may legitimately return to another host of the same proxy.
    /// </remarks>
    public static AuthenticationProperties CreateChallengeProperties(HttpContext context, ITenantResolver tenantResolver, string returnUrl) =>
        BuildChallengeProperties(context, tenantResolver, NormalizeReturnUrl(returnUrl));

    /// <summary>
    /// Creates challenge properties for a sign-in that may return to another host of the same proxy.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="tenantResolver">The tenant resolver used to capture tenant metadata.</param>
    /// <param name="returnUrl">The return URL to use after successful authentication.</param>
    /// <param name="config">The auth proxy configuration deciding which absolute return URLs are honored.</param>
    /// <returns>An <see cref="AuthenticationProperties"/> initialized for the challenge.</returns>
    /// <remarks>
    /// See <see cref="SignInReturnUrl"/>: without <see cref="C.SignIn.CallbackHost"/> this is the same as the overload
    /// without the configuration.
    /// </remarks>
    public static AuthenticationProperties CreateChallengeProperties(HttpContext context, ITenantResolver tenantResolver, string returnUrl, C.AuthProxy config) =>
        BuildChallengeProperties(context, tenantResolver, SignInReturnUrl.Resolve(context, config, returnUrl));

    /// <summary>
    /// Tries to resolve a post-authentication redirect URI from tenant metadata in state.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="properties">The round-tripped authentication properties.</param>
    /// <param name="currentReturnUri">The current handler return URI.</param>
    /// <param name="redirectUri">The resolved redirect URI when successful.</param>
    /// <returns><see langword="true"/> if a redirect URI was resolved; otherwise <see langword="false"/>.</returns>
    public static bool TryResolvePostAuthenticationRedirectUri(
        HttpContext context,
        AuthenticationProperties properties,
        string? currentReturnUri,
        out string redirectUri)
    {
        redirectUri = string.Empty;

        if (!TryReadTenantMetadata(properties, out var tenantId, out var strategy))
        {
            return false;
        }

        if (strategy != C.TenantSourceIdentifierResolverType.SubHost)
        {
            return false;
        }

        var returnUrl = NormalizeReturnUrl(currentReturnUri ?? properties.RedirectUri ?? "/");
        var subHostRedirect = BuildSubHostRedirect(context.Request, properties, new HostLabel(tenantId), returnUrl);
        if (subHostRedirect is null)
        {
            return false;
        }

        redirectUri = subHostRedirect;
        return true;
    }

    /// <summary>
    /// Reduces a caller-supplied return URL to a target that can only navigate within this site.
    /// </summary>
    /// <param name="returnUrl">The caller-supplied return URL.</param>
    /// <returns>A same-site relative target, or the application root when none can be derived.</returns>
    /// <remarks>
    /// This value survives the round-trip to the identity provider and is handed to the browser as the
    /// post-authentication <c language="text">Location</c>, so it is the single most attractive open-redirect target in
    /// AuthProxy: the victim sees the real domain and completes a real login before it is honored. It
    /// arrives from an <c language="text">AllowAnonymous</c> endpoint, so it is attacker-supplied by default.
    /// <para>
    /// An <em>http(s)</em> absolute URL is reduced to its path and query rather than refused, which keeps a
    /// caller that sends its own origin working — the host is dropped, never honored. Any other scheme is
    /// refused outright, and so is anything that cannot be reduced to a verified same-site relative target.
    /// </para>
    /// <para>
    /// The scheme check is doing more work than it looks like. On Unix, <see cref="Uri.TryCreate(string, UriKind, out Uri)"/>
    /// parses a rooted path as an absolute <c language="text">file:</c> URI, so without it <c language="text">//evil.test/phish</c> and
    /// <c language="text">/\t/evil.test</c> would be run through <see cref="Uri.AbsolutePath"/> — laundering a target this
    /// method had just rejected into one that looks clean, and doing it on Linux but not on Windows.
    /// </para>
    /// </remarks>
    internal static string NormalizeReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return RelativeRedirect.ApplicationRoot;
        }

        if (RelativeRedirect.IsSameSiteRelative(returnUrl))
        {
            return returnUrl;
        }

        return Uri.TryCreate(returnUrl, UriKind.Absolute, out var absoluteUri)
            ? ReduceAbsoluteUrl(absoluteUri)
            : RelativeRedirect.Resolve($"/{returnUrl}");
    }

    static string ReduceAbsoluteUrl(Uri absoluteUri) =>
        IsHttpScheme(absoluteUri)
            ? RelativeRedirect.Resolve($"{absoluteUri.AbsolutePath}{absoluteUri.Query}")
            : RelativeRedirect.ApplicationRoot;

    static bool IsHttpScheme(Uri uri) => uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps;

    static bool TryReadTenantMetadata(AuthenticationProperties properties, out string tenantId, out C.TenantSourceIdentifierResolverType strategy)
    {
        tenantId = string.Empty;
        strategy = default;
        if (!properties.Items.TryGetValue(TenantIdStateKey, out var value) || string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (!properties.Items.TryGetValue(StrategyStateKey, out var strategyText)
            || !Enum.TryParse(strategyText, true, out strategy))
        {
            return false;
        }

        tenantId = value;
        return true;
    }

    static string? BuildSubHostRedirect(HttpRequest request, AuthenticationProperties properties, HostLabel tenant, string returnUrl)
    {
        if (!properties.Items.TryGetValue(SubHostParentHostStateKey, out var parentHost)
            || string.IsNullOrWhiteSpace(parentHost))
        {
            return null;
        }

        var normalizedParentHost = parentHost.Trim().TrimStart('.');
        if (!tenant.IsValid || string.IsNullOrWhiteSpace(normalizedParentHost))
        {
            return null;
        }

        return BuildAbsoluteRedirectUri(request, tenant.Under(normalizedParentHost), returnUrl);
    }

    static AuthenticationProperties BuildChallengeProperties(HttpContext context, ITenantResolver tenantResolver, string redirectUri)
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri = redirectUri
        };

        if (!tenantResolver.TryResolve(context, out TenantResolutionResult result)
            || string.IsNullOrWhiteSpace(result.TenantId))
        {
            return properties;
        }

        properties.Items[TenantIdStateKey] = result.TenantId;
        properties.Items[StrategyStateKey] = result.Strategy.ToString();

        if (result.Strategy == C.TenantSourceIdentifierResolverType.SubHost
            && !string.IsNullOrWhiteSpace(result.SubHostParentHost))
        {
            properties.Items[SubHostParentHostStateKey] = result.SubHostParentHost.Trim().TrimStart('.');
        }

        return properties;
    }

    static string BuildAbsoluteRedirectUri(HttpRequest request, string host, string returnUrl)
    {
        var queryStart = returnUrl.IndexOf('?');
        var path = queryStart >= 0 ? returnUrl[..queryStart] : returnUrl;
        var query = queryStart >= 0 ? returnUrl[(queryStart + 1)..] : string.Empty;

        var builder = new UriBuilder(request.Scheme, host)
        {
            Path = string.IsNullOrWhiteSpace(path) ? "/" : path,
            Query = query,
        };

        return builder.Uri.ToString();
    }
}