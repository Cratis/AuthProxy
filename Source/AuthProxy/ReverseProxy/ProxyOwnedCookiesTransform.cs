// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Yarp.ReverseProxy.Transforms;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Removes the cookies AuthProxy owns from the <c language="text">Cookie</c> header before a request reaches a service.
/// </summary>
/// <remarks>
/// The session cookie (and its chunks) and the cookies in <see cref="Cookies"/> exist for AuthProxy alone. Every
/// other cookie is forwarded exactly as it arrived, in the same order.
/// </remarks>
public class ProxyOwnedCookiesTransform : RequestTransform
{
    static readonly HashSet<string> _proxyCookies = new(StringComparer.Ordinal)
    {
        Cookies.Identity,
        Cookies.IdentityAuthorization,
        Cookies.EntryTransaction,
        Cookies.OnBehalf,
        Cookies.InviteToken,
        Cookies.InvitationEntryState,
        Cookies.Registration,
        Cookies.Providers,
        Cookies.Tenants,
        Cookies.Tenant,
        Cookies.LogoutRedirect
    };

    /// <inheritdoc/>
    public override ValueTask ApplyAsync(RequestTransformContext context)
    {
        if (!context.ProxyRequest.Headers.TryGetValues(HeaderNames.Cookie, out var values))
        {
            return ValueTask.CompletedTask;
        }

        var options = context.HttpContext.RequestServices.GetRequiredService<IOptionsMonitor<C.AuthProxy>>().CurrentValue;
        var sessionCookie = SessionCookie.NameOf(options.Session);
        var affinityCookies = options.Services.Keys
            .Select(key => Cookies.AffinityFor(key.ToLowerInvariant()))
            .ToHashSet(StringComparer.Ordinal);

        var kept = values
            .SelectMany(value => value.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            .Where(pair => !IsOwnedByProxy(pair, sessionCookie, affinityCookies))
            .ToArray();

        context.ProxyRequest.Headers.Remove(HeaderNames.Cookie);
        if (kept.Length > 0)
        {
            context.ProxyRequest.Headers.TryAddWithoutValidation(HeaderNames.Cookie, string.Join("; ", kept));
        }

        return ValueTask.CompletedTask;
    }

    static bool IsOwnedByProxy(string pair, string sessionCookie, HashSet<string> affinityCookies)
    {
        var separator = pair.IndexOf('=', StringComparison.Ordinal);
        var name = separator < 0 ? pair : pair[..separator].Trim();
        return _proxyCookies.Contains(name) || affinityCookies.Contains(name) || SessionCookieHealing.BelongsTo(sessionCookie, name);
    }
}
