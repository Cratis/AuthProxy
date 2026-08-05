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
    public static AuthenticationProperties CreateChallengeProperties(HttpContext context, ITenantResolver tenantResolver, string returnUrl)
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri = NormalizeReturnUrl(returnUrl)
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

        if (!properties.Items.TryGetValue(TenantIdStateKey, out var tenantId)
            || string.IsNullOrWhiteSpace(tenantId)
            || !properties.Items.TryGetValue(StrategyStateKey, out var strategyText)
            || !Enum.TryParse<C.TenantSourceIdentifierResolverType>(strategyText, true, out var strategy))
        {
            return false;
        }

        var returnUrl = NormalizeReturnUrl(currentReturnUri ?? properties.RedirectUri ?? "/");

        if (strategy == C.TenantSourceIdentifierResolverType.SubHost)
        {
            if (!properties.Items.TryGetValue(SubHostParentHostStateKey, out var parentHost)
                || string.IsNullOrWhiteSpace(parentHost))
            {
                return false;
            }

            var normalizedParentHost = parentHost.Trim().TrimStart('.');
            if (!IsValidHostLabel(tenantId) || string.IsNullOrWhiteSpace(normalizedParentHost))
            {
                return false;
            }

            var targetHost = $"{tenantId}.{normalizedParentHost}";
            redirectUri = BuildAbsoluteRedirectUri(context.Request.Scheme, targetHost, returnUrl);
            return true;
        }

        return false;
    }

    /// <summary>
    /// Reduces a caller-supplied return URL to a target that can only navigate within this site.
    /// </summary>
    /// <param name="returnUrl">The caller-supplied return URL.</param>
    /// <returns>A same-site relative target, or the application root when none can be derived.</returns>
    /// <remarks>
    /// This value survives the round-trip to the identity provider and is handed to the browser as the
    /// post-authentication <c>Location</c>, so it is the single most attractive open-redirect target in
    /// AuthProxy: the victim sees the real domain and completes a real login before it is honored. It
    /// arrives from an <c>AllowAnonymous</c> endpoint, so it is attacker-supplied by default.
    /// <para>
    /// An <em>http(s)</em> absolute URL is reduced to its path and query rather than refused, which keeps a
    /// caller that sends its own origin working — the host is dropped, never honored. Any other scheme is
    /// refused outright, and so is anything that cannot be reduced to a verified same-site relative target.
    /// </para>
    /// <para>
    /// The scheme check is doing more work than it looks like. On Unix, <see cref="Uri.TryCreate(string, UriKind, out Uri)"/>
    /// parses a rooted path as an absolute <c>file:</c> URI, so without it <c>//evil.test/phish</c> and
    /// <c>/\t/evil.test</c> would be run through <see cref="Uri.AbsolutePath"/> — laundering a target this
    /// method had just rejected into one that looks clean, and doing it on Linux but not on Windows.
    /// </para>
    /// </remarks>
    static string NormalizeReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return RelativeRedirect.ApplicationRoot;
        }

        if (RelativeRedirect.IsSameSiteRelative(returnUrl))
        {
            return returnUrl;
        }

        if (Uri.TryCreate(returnUrl, UriKind.Absolute, out var absoluteUri))
        {
            return absoluteUri.Scheme == Uri.UriSchemeHttp || absoluteUri.Scheme == Uri.UriSchemeHttps
                ? RelativeRedirect.Resolve($"{absoluteUri.AbsolutePath}{absoluteUri.Query}")
                : RelativeRedirect.ApplicationRoot;
        }

        return RelativeRedirect.Resolve($"/{returnUrl}");
    }

    static string BuildAbsoluteRedirectUri(string scheme, string host, string returnUrl)
    {
        var queryStart = returnUrl.IndexOf('?');
        var path = queryStart >= 0 ? returnUrl[..queryStart] : returnUrl;
        var query = queryStart >= 0 ? returnUrl[(queryStart + 1)..] : string.Empty;

        var builder = new UriBuilder(scheme, host)
        {
            Path = string.IsNullOrWhiteSpace(path) ? "/" : path,
            Query = query,
        };

        return builder.Uri.ToString();
    }

    static bool IsValidHostLabel(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (value.StartsWith('-') || value.EndsWith('-'))
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsLetterOrDigit(character) && character != '-')
            {
                return false;
            }
        }

        return true;
    }
}