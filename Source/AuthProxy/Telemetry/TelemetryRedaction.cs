// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace Cratis.AuthProxy.Telemetry;

/// <summary>
/// Removes what the shared ASP.NET Core and HTTP client instrumentation would otherwise record about a request
/// and that carries a credential or a tenant: an invitation token in the path, a query string, a tenant in a
/// verification URL, and a tenant in a subdomain.
/// </summary>
/// <remarks>
/// Both the stable and the older attribute names are covered, because which of them an instrumentation version
/// emits depends on its semantic-convention opt-in.
/// </remarks>
public static class TelemetryRedaction
{
    /// <summary>
    /// The path recorded in place of an invitation path, which carries the invitation token.
    /// </summary>
    public const string RedactedInvitePath = $"{WellKnownPaths.InvitePathPrefix}/{{token}}";

    static readonly string[] _queryTags = ["url.query", "http.query"];
    static readonly string[] _serverHostTags = ["server.address", "server.port", "http.host", "net.host.name"];
    static readonly string[] _clientHostTags = ["server.address", "server.port", "http.host", "net.peer.name", "net.peer.port", "network.peer.address", "dns.question.name"];
    static readonly string[] _fullUrlTags = ["url.full", "http.url"];
    static readonly string[] _clientUrlTags = ["url.path", "http.target"];
    static readonly string[] _serverPathTags = ["url.path", "http.target"];

    /// <summary>
    /// Redacts the tags of a server span or an outgoing client span, whichever <paramref name="activity"/> is.
    /// </summary>
    /// <param name="activity">The span to redact.</param>
    public static void Redact(Activity activity)
    {
        // Never a query string: callback requests carry the authorization code and state in it.
        Clear(activity, _queryTags);
        Clear(activity, _fullUrlTags);

        if (activity.Kind == ActivityKind.Server)
        {
            // The host of a subdomain-tenancy request is the tenant.
            Clear(activity, _serverHostTags);
            foreach (var key in _serverPathTags)
            {
                RedactPath(activity, key);
            }

            return;
        }

        // An outgoing URL names the tenant the verifier is asked about, or whatever path was forwarded.
        Clear(activity, _clientUrlTags);
        Clear(activity, _clientHostTags);
    }

    static void RedactPath(Activity activity, string key)
    {
        if (activity.GetTagItem(key) is not string value)
        {
            return;
        }

        var queryStart = value.IndexOf('?', StringComparison.Ordinal);
        var path = queryStart < 0 ? value : value[..queryStart];
        activity.SetTag(key, new PathString(path).StartsWithSegments(WellKnownPaths.InvitePathPrefix) ? RedactedInvitePath : path);
    }

    static void Clear(Activity activity, string[] keys)
    {
        foreach (var key in keys)
        {
            activity.SetTag(key, null);
        }
    }
}
