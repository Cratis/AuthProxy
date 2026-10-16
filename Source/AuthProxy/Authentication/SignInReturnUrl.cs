// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Decides where a person may be sent after signing in.
/// </summary>
/// <remarks>
/// The value survives the round trip to the identity provider and is handed to the browser as the post-authentication
/// <c language="text">Location</c>, and it arrives from an anonymous endpoint, so it is attacker-supplied by default. Without a
/// <see cref="C.SignIn.CallbackHost"/> it is reduced to a same-site relative path exactly as it always was. With one,
/// an absolute URL is kept only when its origin is on the shared <see cref="AllowedOrigins"/> list and its host lies
/// inside the session cookie domain — anything else is reduced to a path on this host, or to the root.
/// </remarks>
public static class SignInReturnUrl
{
    /// <summary>
    /// Resolves the destination to use after a sign-in.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="config">The auth proxy configuration.</param>
    /// <param name="returnUrl">The caller-supplied return URL.</param>
    /// <returns>An allow-listed absolute URL, or a same-site relative path.</returns>
    public static string Resolve(HttpContext context, C.AuthProxy config, string? returnUrl)
    {
        if (SignInCallbackHost.IsConfigured(config)
            && !string.IsNullOrWhiteSpace(returnUrl)
            && !RelativeRedirect.IsSameSiteRelative(returnUrl)
            && Uri.TryCreate(returnUrl, UriKind.Absolute, out var absolute)
            && (absolute.Scheme == Uri.UriSchemeHttp || absolute.Scheme == Uri.UriSchemeHttps)
            && AllowedOrigins.ContainsWithinCookieDomain(context, config, absolute))
        {
            return $"{absolute.GetLeftPart(UriPartial.Authority)}{RelativeRedirect.Resolve($"{absolute.AbsolutePath}{absolute.Query}")}";
        }

        return TenantAuthenticationState.NormalizeReturnUrl(returnUrl);
    }
}
