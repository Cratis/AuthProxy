// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Ingress;

/// <summary>
/// Refuses configured public-host paths before any request handling or rewriting.
/// </summary>
/// <param name="next">The next middleware.</param>
/// <param name="ingress">The validated ingress configuration.</param>
/// <param name="logger">The logger.</param>
public class DeniedPathMiddleware(RequestDelegate next, IOptions<C.Ingress> ingress, ILogger<DeniedPathMiddleware> logger)
{
    readonly string[] _prefixes = [.. ingress.Value.DeniedPathPrefixes.Select(prefix =>
    {
        DeniedPathNormalization.TryNormalize(prefix, out var normalized);
        return normalized;
    })];

    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public Task InvokeAsync(HttpContext context)
    {
        if (_prefixes.Length == 0) return next(context);

        // RawTarget preserves escapes and the original public path, even if PathBase/Path was split or
        // normalized. Never fall back to Path: Kestrel has already decoded it and resolved dot segments.
        var target = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (DeniedPathNormalization.TryNormalize(target, out var path) && !_prefixes.Any(prefix => Matches(path, prefix)))
        {
            return next(context);
        }

        logger.PathRefused();
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return Task.CompletedTask;
    }

    static bool Matches(string path, string prefix) =>
        prefix == "/"
        || path.Equals(prefix, StringComparison.OrdinalIgnoreCase)
        || path.StartsWith($"{prefix}/", StringComparison.OrdinalIgnoreCase);
}
