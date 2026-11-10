// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Validates explicit route opt-in and its shared-store prerequisites.</summary>
internal static class DpopConfiguration
{
    /// <summary>Collects startup failures without including configuration secrets.</summary>
    /// <param name="route">The route.</param>
    /// <param name="options">The deployment configuration.</param>
    /// <param name="at">The configuration location.</param>
    /// <param name="failures">The startup failures.</param>
    internal static void Validate(C.BearerRoute route, C.AuthProxy options, string at, List<string> failures)
    {
        if (route.Dpop is not { } policy) return;
        ValidateRoute(route, at, failures);
        ValidateMapping(policy, at, failures);
        ValidateReplay(options.Dpop.ReplayStore.Redis, at, failures);
    }

    static void ValidateRoute(C.BearerRoute route, string at, List<string> failures)
    {
        if (route.PersonalAccessTokens is not null || route.Issuers.Count == 0) failures.Add($"{at}:Dpop requires an OAuth-only route.");
        if (route.IntrospectionUnavailable != C.IntrospectionFailurePolicy.Refuse) failures.Add($"{at}:Dpop requires fail-closed introspection.");
        if (route.ForwardAuthorizationHeader) failures.Add($"{at}:Dpop cannot forward the Authorization header.");
    }

    static void ValidateMapping(C.BearerRouteDpop policy, string at, List<string> failures)
    {
        if (!DpopTargetUri.TryOrigin(policy.PublicOrigin, out _)) failures.Add($"{at}:Dpop:PublicOrigin must be a trusted HTTPS origin without a path, query or fragment.");
        if (!Enum.IsDefined(policy.Mode)) failures.Add($"{at}:Dpop:Mode must be Accept or Require.");
        if (policy.PublicPathPrefix is { } path && !ValidPrefix(path)) failures.Add($"{at}:Dpop:PublicPathPrefix must be an unambiguous escaped absolute path prefix without a trailing slash.");
    }

    static void ValidateReplay(C.DpopRedis redis, string at, List<string> failures)
    {
        if (string.IsNullOrWhiteSpace(redis.ConnectionString)) failures.Add($"{at}:Dpop requires Dpop:ReplayStore:Redis:ConnectionString.");
        if (!ValidKeyPrefix(redis.KeyPrefix)) failures.Add($"{at}:Dpop:ReplayStore:Redis:KeyPrefix must be bounded printable ASCII without braces.");
    }

    static bool ValidPrefix(string path) => DpopTargetUri.ValidPath(path) && !path.Contains("%2f", StringComparison.OrdinalIgnoreCase) && (path.Length == 1 || !path.EndsWith('/'));
    static bool ValidKeyPrefix(string key) => key.Length is >= 1 and <= 128 && key.All(character => character is >= '!' and <= '~' and not '{' and not '}');
}
