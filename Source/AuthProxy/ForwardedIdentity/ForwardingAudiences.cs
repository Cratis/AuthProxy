// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Tenancy;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>
/// Decides which audience an outbound request is signed for.
/// </summary>
/// <remarks>
/// The audience names the service the request is for, so a backend cannot replay an assertion it received to a
/// sibling service. A configured service's audience is its <see cref="C.Service.ForwardingAudience"/>, or its
/// configuration key. The tenant-selection endpoint is configured as a URL rather than as a service, so its audience
/// is the audience of the service that serves it.
/// </remarks>
static class ForwardingAudiences
{
    /// <summary>
    /// Gets the audience of a configured service.
    /// </summary>
    /// <param name="config">The auth proxy configuration.</param>
    /// <param name="serviceName">The configuration key of the service.</param>
    /// <returns>The service's forwarding audience, or its key when it states none.</returns>
    internal static string For(C.AuthProxy config, string serviceName) =>
        config.Services.TryGetValue(serviceName, out var service) && service.ForwardingAudience is not null
            ? service.ForwardingAudience
            : serviceName;

    /// <summary>
    /// Gets the audience of the call to the tenant-selection endpoint.
    /// </summary>
    /// <param name="config">The auth proxy configuration.</param>
    /// <param name="selection">The selection strategy options carrying the endpoint.</param>
    /// <param name="ambiguous">Whether services sharing the endpoint's origin and path disagree on the audience.</param>
    /// <returns>The audience, or <see langword="null"/> when none can be resolved.</returns>
    /// <remarks>
    /// The endpoint belongs to the configured service whose backend has the same scheme, host and port. When several
    /// do, the one whose backend base path is the longest prefix of the endpoint's path wins. When they still disagree,
    /// or when no service serves the endpoint, the explicit <see cref="SelectionOptions.ForwardingAudience"/> is used.
    /// </remarks>
    internal static string? ForTenantSelection(C.AuthProxy config, SelectionOptions selection, out bool ambiguous)
    {
        ambiguous = false;
        if (!Uri.TryCreate(selection.TenantsEndpoint, UriKind.Absolute, out var endpoint))
        {
            return selection.ForwardingAudience;
        }

        var sameOrigin = config.Services
            .Select(_ => (Name: _.Key, BaseUrl: BaseUrlOf(_.Value)))
            .Where(_ => _.BaseUrl is not null && IsSameOrigin(_.BaseUrl, endpoint))
            .ToArray();
        if (sameOrigin.Length == 0)
        {
            return selection.ForwardingAudience;
        }

        var byPath = sameOrigin.Where(_ => IsPathPrefix(BasePath(_.BaseUrl!), endpoint.AbsolutePath)).ToArray();
        var longest = byPath.Length == 0 ? 0 : byPath.Max(_ => BasePath(_.BaseUrl!).Length);
        var serving = byPath.Length == 0 ? sameOrigin : byPath.Where(_ => BasePath(_.BaseUrl!).Length == longest).ToArray();
        var audiences = serving.Select(_ => For(config, _.Name)).Distinct(StringComparer.Ordinal).ToArray();
        if (audiences.Length == 1)
        {
            return audiences[0];
        }

        ambiguous = selection.ForwardingAudience is null;
        return selection.ForwardingAudience;
    }

    static Uri? BaseUrlOf(C.Service service) =>
        Uri.TryCreate(service.Backend?.BaseUrl, UriKind.Absolute, out var baseUrl) ? baseUrl : null;

    static bool IsSameOrigin(Uri left, Uri right) =>
        string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.IdnHost, right.IdnHost, StringComparison.OrdinalIgnoreCase)
        && left.Port == right.Port;

    static string BasePath(Uri baseUrl) => baseUrl.AbsolutePath.TrimEnd('/');

    static bool IsPathPrefix(string basePath, string path) =>
        basePath.Length == 0
        || string.Equals(path, basePath, StringComparison.Ordinal)
        || path.StartsWith($"{basePath}/", StringComparison.Ordinal);
}
