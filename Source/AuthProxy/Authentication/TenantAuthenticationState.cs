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

    static string NormalizeReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return "/";
        }

        if (returnUrl.StartsWith('/'))
        {
            return returnUrl;
        }

        if (Uri.TryCreate(returnUrl, UriKind.Absolute, out var absoluteUri))
        {
            return $"{absoluteUri.AbsolutePath}{absoluteUri.Query}";
        }

        return $"/{returnUrl}";
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