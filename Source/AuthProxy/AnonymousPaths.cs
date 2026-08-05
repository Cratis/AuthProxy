// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// Resolves the anonymous path prefixes declared in <see cref="C.Service.AnonymousPaths"/>.
/// </summary>
/// <remarks>
/// Four components have to agree on what counts as an anonymous path — <c>SelectProviderMiddleware</c>
/// (do not serve the provider-selection page), <c>TenantSelectionMiddleware</c> (do not serve the
/// tenant chooser to a signed-in caller who has not chosen one), <c>TenancyMiddleware</c> (do not refuse
/// a caller with no resolvable tenant), and the reverse-proxy route table (do not apply the
/// authenticated-user authorization policy). If one disagreed the path would still be unreachable and the
/// disagreement would be silent, so they all resolve through here.
/// <para>
/// The middlewares match with <see cref="PathString.StartsWithSegments(PathString)"/> while the route
/// table matches an ASP.NET route template built from the same prefix. Those two agree only for a prefix
/// made of plain literal segments, which is what <see cref="AnonymousPathPolicy"/> enforces: anything else
/// is discarded rather than matched, so a prefix can never mean one thing to a middleware and another to
/// the router.
/// </para>
/// </remarks>
public static class AnonymousPaths
{
    /// <summary>
    /// The usable prefixes resolved for a configuration instance, so <see cref="Matches"/> does not re-parse
    /// every declared entry on every request. Weak keys, so a superseded configuration is collectable.
    /// </summary>
    static readonly ConditionalWeakTable<C.AuthProxy, string[]> _resolvedPrefixes = [];

    /// <summary>
    /// Gets the usable, de-duplicated anonymous path prefixes declared by a single service.
    /// </summary>
    /// <param name="service">The service to read.</param>
    /// <returns>The service's anonymous path prefixes.</returns>
    public static IEnumerable<string> For(C.Service service) =>
        Evaluate(service)
            .Where(_ => _.IsUsable)
            .Select(_ => _.Prefix)
            .Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Evaluates every entry a service declares, keeping the refused ones and the reason for each.
    /// </summary>
    /// <param name="service">The service to read.</param>
    /// <returns>One evaluation per declared entry, in declaration order.</returns>
    /// <remarks>
    /// <see cref="For(C.Service)"/> answers what is anonymous; this answers what was <em>asked</em> for and
    /// refused, which is the part an operator cannot otherwise see. A refusal is fail-closed, so nothing
    /// breaks loudly — the path simply keeps asking for a login — and without this the only symptom of a
    /// typo in a declared prefix is a surface that was meant to be public quietly not being.
    /// </remarks>
    public static IEnumerable<AnonymousPathEvaluation> Evaluate(C.Service service) =>
        service.AnonymousPaths.Select(candidate =>
        {
            var rejection = AnonymousPathPolicy.Evaluate(candidate, out var prefix);
            return new AnonymousPathEvaluation(candidate ?? string.Empty, prefix, rejection);
        });

    /// <summary>
    /// Determines whether the given request path is covered by a declared anonymous path prefix.
    /// </summary>
    /// <param name="path">The request path to evaluate.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns><see langword="true"/> when the path is anonymous; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// This runs on every request through three middlewares, so the normalized prefixes are resolved once per
    /// configuration rather than re-parsed per call: <see cref="TryNormalize"/> trims and scans every declared
    /// entry, which was three passes over every entry on every request purely to arrive at the same strings.
    /// <para>
    /// Keyed on the configuration instance, so correctness does not depend on noticing a change.
    /// <see cref="Microsoft.Extensions.Options.IOptionsMonitor{T}"/> hands out a new instance when
    /// configuration reloads, which misses the cache and resolves again; the table holds its keys weakly, so a
    /// superseded configuration is collectable. A cache that had to be invalidated explicitly could leave a
    /// prefix anonymous after it was removed, which is the one failure mode worth engineering out here.
    /// </para>
    /// </remarks>
    public static bool Matches(PathString path, C.AuthProxy config)
    {
        var prefixes = _resolvedPrefixes.GetValue(config, Resolve);

        // Nothing declared is the case every deployment that never opts in is in, so it costs a length check.
        for (var i = 0; i < prefixes.Length; i++)
        {
            if (path.StartsWithSegments(prefixes[i]))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Normalizes a declared entry into a usable path prefix.
    /// </summary>
    /// <param name="candidate">The declared entry.</param>
    /// <param name="prefix">The normalized prefix when the entry is usable.</param>
    /// <returns><see langword="true"/> when the entry is usable; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Every rejection is fail-closed — a discarded entry leaves the path authenticated, never the other
    /// way around. <see cref="AnonymousPathPolicy"/> owns the rules and the reason for each; this is the
    /// boolean form for callers that only need to know whether an entry survived.
    /// </remarks>
    public static bool TryNormalize(string? candidate, out string prefix) =>
        AnonymousPathPolicy.Evaluate(candidate, out prefix) == AnonymousPathRejection.None;

    static string[] Resolve(C.AuthProxy config) =>
        [.. config.Services.Values
            .SelectMany(For)
            .Distinct(StringComparer.OrdinalIgnoreCase)];
}
