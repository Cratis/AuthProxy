// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A deployment with freshness rules but no forwarding-path rules.</summary>
public class FreshAuthenticationHarness : BearerRouteHarness
{
    /// <inheritdoc/>
    protected override bool UsesHeaderAuthentication => false;

    /// <summary>Gets or sets the attestation; null omits it to exercise fail-closed startup.</summary>
    public bool? MethodOverrideUnsupported { get; set; } = true;

    /// <summary>Builds a request with a real cookie whose authentication age is independent of its ticket lifetime.</summary>
    /// <param name="method">The transport method.</param>
    /// <param name="path">The path and query to request.</param>
    /// <param name="authenticationAge">The authentication age, defaulting to a stale ten-minute session.</param>
    /// <returns>The request carrying a protected cookie ticket.</returns>
    public HttpRequestMessage WithSession(HttpMethod method, string path, TimeSpan? authenticationAge = null)
    {
        var options = Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);
        var user = SecurityHarness.UniqueUser("freshness-session");
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, user), new Claim(ClaimTypes.Name, user)],
            CookieAuthenticationDefaults.AuthenticationScheme));
        var now = DateTimeOffset.UtcNow;
        var properties = new AuthenticationProperties { IssuedUtc = now, ExpiresUtc = now.AddHours(1) };
        SessionProvider.Stamp(principal, properties, OidcProviderScheme.FromName("Provider One"));
        SessionAuthenticationTime.Stamp(principal, properties, now - (authenticationAge ?? TimeSpan.FromMinutes(10)));
        var ticket = new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme);
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        options.CookieManager.AppendResponseCookie(context, options.Cookie.Name, options.TicketDataFormat.Protect(ticket), options.Cookie.Build(context));
        var request = new HttpRequestMessage(method, path);
        request.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", context.Response.Headers.SetCookie.Select(cookie => cookie.Split(';', 2)[0])));
        return request;
    }

    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        const string service = $"{C.AuthProxy.SectionKey}:Services:app";
        settings[$"{service}:ResolveIdentityDetails"] = "false";
        if (MethodOverrideUnsupported is { } attested)
        {
            settings[$"{service}:FreshAuthenticationMethodOverrideUnsupported"] = attested.ToString();
        }
        string[] paths = ["/mcp/approve", "/v1/approve", "/approve", ResourceMetadataPath];
        for (var index = 0; index < paths.Length; index++)
        {
            var rule = $"{service}:FreshAuthentication:{index}";
            settings[$"{rule}:Path"] = paths[index];
            settings[$"{rule}:MaxAge"] = "00:05:00";
            if (paths[index] != ResourceMetadataPath)
            {
                settings[$"{rule}:Methods:0"] = "DELETE";
            }
        }
    }
}
