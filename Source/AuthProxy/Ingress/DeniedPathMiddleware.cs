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
    readonly string[] _prefixes = [.. ingress.Value.DeniedPathPrefixes
        .Select(prefix => DeniedPathNormalization.NormalizeSeparators(prefix).TrimEnd('/'))];

    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public Task InvokeAsync(HttpContext context)
    {
        if (_prefixes.Length == 0) return next(context);

        // Retain the server's path checks and also normalize the original target: Kestrel may
        // remove dot segments before encoded separators or repeated slashes are normalized.
        var path = string.Concat(context.Request.PathBase.Value, context.Request.Path.Value);
        if (!IsDenied(path, context.Features.Get<IHttpRequestFeature>()?.RawTarget))
        {
            return next(context);
        }

        logger.PathRefused();
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return Task.CompletedTask;
    }

    static bool Matches(string path, string prefix) =>
        prefix.Length == 0
        || path.Equals(prefix, StringComparison.OrdinalIgnoreCase)
        || path.StartsWith($"{prefix}/", StringComparison.OrdinalIgnoreCase);

    bool IsDenied(string path, string? rawTarget)
    {
        if (!DeniedPathNormalization.TryNormalize(path, out var alternative)) return true;
        if (_prefixes.Any(prefix => Matches(path, prefix) || Matches(alternative, prefix))) return true;
        return IsRawTargetDenied(rawTarget);
    }

    bool IsRawTargetDenied(string? rawTarget)
    {
        if (string.IsNullOrEmpty(rawTarget)) return false;
        if (!DeniedPathNormalization.TryNormalizeRawTarget(rawTarget, out var path)) return true;
        return _prefixes.Any(prefix => Matches(path, prefix));
    }
}
