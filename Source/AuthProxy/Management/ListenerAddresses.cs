// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;

namespace Cratis.AuthProxy.Management;

/// <summary>
/// Represents the addresses AuthProxy was already told to listen on, resolved exactly the way the host
/// resolves them.
/// </summary>
/// <remarks>
/// Adding a listener means re-declaring the existing ones alongside it, so what they are has to be answered
/// before anything is changed. The host resolves them in a specific order — the <c>urls</c> setting first
/// (<c>ASPNETCORE_URLS</c>), then the <c>HTTP_PORTS</c> and <c>HTTPS_PORTS</c> settings, which is how the
/// official .NET container images publish port 8080 — and reading only the first of those would silently
/// unbind the public listener of every containerized deployment.
/// </remarks>
public sealed class ListenerAddresses
{
    /// <summary>
    /// The address the host binds when a deployment declares none at all. Named here because re-declaring
    /// the listeners means declaring this one too; leaving it out would replace the development-time
    /// default with the management listener rather than adding to it.
    /// </summary>
    public const string HostDefault = "http://localhost:5000";

    ListenerAddresses(IReadOnlyList<string> declared) => Declared = declared;

    /// <summary>
    /// Gets the addresses AuthProxy listens on before the management listener is added.
    /// </summary>
    public IReadOnlyList<string> Declared { get; }

    /// <summary>
    /// Resolves the addresses the host would bind for the given configuration.
    /// </summary>
    /// <param name="configuration">The configuration the host was built from.</param>
    /// <returns>The resolved addresses.</returns>
    public static ListenerAddresses Resolve(IConfiguration configuration)
    {
        var urls = Split(configuration[WebHostDefaults.ServerUrlsKey]);

        if (urls.Count == 0)
        {
            urls =
            [
                .. Expand(configuration[WebHostDefaults.HttpPortsKey], Uri.UriSchemeHttp),
                .. Expand(configuration[WebHostDefaults.HttpsPortsKey], Uri.UriSchemeHttps)
            ];
        }

        return new(urls.Count == 0 ? [HostDefault] : urls);
    }

    /// <summary>
    /// Gets the port an address names.
    /// </summary>
    /// <param name="address">The address, for example <c>http://+:8080</c> or <c>http://[::1]:9110</c>.</param>
    /// <returns>The port, or <see langword="null"/> when the address names none.</returns>
    public static int? PortOf(string address)
    {
        var schemeEnd = address.IndexOf("://", StringComparison.Ordinal);
        var start = schemeEnd < 0 ? 0 : schemeEnd + 3;
        var pathStart = address.IndexOf('/', start);
        var authority = pathStart < 0 ? address[start..] : address[start..pathStart];
        var separator = authority.LastIndexOf(':');

        // A bracketed IPv6 host is full of colons, so a colon inside the brackets is not a port separator.
        if (separator < 0 || separator < authority.LastIndexOf(']'))
        {
            return null;
        }

        return int.TryParse(authority[(separator + 1)..], CultureInfo.InvariantCulture, out var port) ? port : null;
    }

    /// <summary>
    /// Gets whether any already-declared address binds a port.
    /// </summary>
    /// <param name="port">The port to look for.</param>
    /// <returns><see langword="true"/> when one of them binds it; otherwise <see langword="false"/>.</returns>
    public bool Uses(int port) => Declared.Any(address => PortOf(address) == port);

    /// <summary>
    /// Gets the declared addresses together with one more.
    /// </summary>
    /// <param name="address">The address to add.</param>
    /// <returns>Every address the host should be told to bind.</returns>
    public IReadOnlyList<string> Including(string address) => [.. Declared, address];

    static List<string> Split(string? value) =>
        [.. (value ?? string.Empty).Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

    static IEnumerable<string> Expand(string? ports, string scheme) =>
        Split(ports).Select(port => $"{scheme}://*:{port}");
}
