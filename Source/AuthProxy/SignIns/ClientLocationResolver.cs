// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// Resolves the approximate origin of a request from its client IP address and any geo headers a fronting
/// CDN or reverse proxy may add.
/// </summary>
/// <remarks>
/// <para>
/// AuthProxy deliberately does not bundle a geo-IP database — that would be a heavy dependency and a data
/// pipeline of its own. Instead the location is derived from what is already on the request:
/// </para>
/// <list type="bullet">
///   <item>the client IP, taken from the left-most entry of <c>X-Forwarded-For</c> (falling back to the
///   connection's remote address), which the forwarded-headers middleware has already normalized; and</item>
///   <item>coarse geo headers that popular fronting layers add — Cloudflare's <c>CF-IPCountry</c>, and the
///   conventional <c>X-Geo-*</c> / <c>X-AppEngine-*</c> city/region/country headers.</item>
/// </list>
/// <para>
/// When no geo headers are present the location is left empty and only the IP travels; the application can
/// resolve a fuller location from the IP later if it chooses. This keeps AuthProxy dependency-light while
/// still recording a genuine approximate location wherever the infrastructure provides one.
/// </para>
/// </remarks>
public class ClientLocationResolver : IClientLocationResolver
{
    static readonly string[] _cityHeaders = ["X-Geo-City", "X-AppEngine-City", "CF-IPCity"];
    static readonly string[] _regionHeaders = ["X-Geo-Region", "X-AppEngine-Region", "CF-Region"];
    static readonly string[] _countryHeaders = ["X-Geo-Country", "X-AppEngine-Country", "CF-IPCountry"];

    /// <inheritdoc/>
    public ClientLocation Resolve(HttpContext context)
    {
        var ipAddress = ResolveIpAddress(context);
        var location = ResolveLocation(context.Request.Headers);
        return new ClientLocation(ipAddress, location);
    }

    static string ResolveIpAddress(HttpContext context)
    {
        // The forwarded-headers middleware normally rewrites the connection's remote address from
        // X-Forwarded-For, but the header is read directly too so the left-most (original client) address is
        // used even when the middleware is not in play or multiple proxies are chained.
        var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(forwardedFor))
        {
            var firstHop = forwardedFor.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(firstHop))
            {
                return firstHop;
            }
        }

        return context.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
    }

    static string ResolveLocation(IHeaderDictionary headers)
    {
        var city = FirstHeaderValue(headers, _cityHeaders);
        var region = FirstHeaderValue(headers, _regionHeaders);
        var country = FirstHeaderValue(headers, _countryHeaders);

        var parts = new[] { city, region, country }.Where(part => !string.IsNullOrWhiteSpace(part));
        return string.Join(", ", parts);
    }

    static string FirstHeaderValue(IHeaderDictionary headers, string[] names)
    {
        foreach (var name in names)
        {
            var value = headers[name].FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }

        return string.Empty;
    }
}
