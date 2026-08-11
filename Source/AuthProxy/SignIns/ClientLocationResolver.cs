// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Ingress;

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
///   <item>the client IP, taken from the connection's remote address as the forwarded-headers middleware
///   left it, which is the address of the trusted proxy's declared client when the request came through
///   the deployment's own infrastructure and the caller's own address otherwise; and</item>
///   <item>coarse geo headers that popular fronting layers add — Cloudflare's <c>CF-IPCountry</c>, and the
///   conventional <c>X-Geo-*</c> / <c>X-AppEngine-*</c> city/region/country headers — read only when the
///   request came from a trusted proxy.</item>
/// </list>
/// <para>
/// When no geo headers are present the location is left empty and only the IP travels; the application can
/// resolve a fuller location from the IP later if it chooses. This keeps AuthProxy dependency-light while
/// still recording a genuine approximate location wherever the infrastructure provides one.
/// </para>
/// <para>
/// Nothing here reads a forwarded header directly. Doing so used to produce two different attacker-chosen
/// answers for one request — the middleware consumes the right-most entry into the connection's remote
/// address and truncates the header, so reading the surviving left-most entry reported an address that was
/// not the one anything else in the proxy was using. Both values are only ever as trustworthy as the caller
/// that sent them, and only the middleware knows whether that caller was trusted.
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
        var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        var location = context.IsFromTrustedProxy()
            ? ResolveLocation(context.Request.Headers)
            : string.Empty;

        return new ClientLocation(ipAddress, location);
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
