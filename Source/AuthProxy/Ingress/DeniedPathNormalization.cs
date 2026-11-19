// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.RegularExpressions;

namespace Cratis.AuthProxy.Ingress;

/// <summary>
/// Produces a separator-only alternative to the path already decoded and normalized by the server.
/// </summary>
public static partial class DeniedPathNormalization
{
    [GeneratedRegex("/{2,}", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex RepeatedSlashes { get; }

    /// <summary>
    /// Maps remaining encoded separators and backslashes to slashes, then collapses repeated slashes.
    /// Does not decode other characters or resolve dot segments: those are the server's responsibility.
    /// </summary>
    /// <param name="path">The combined Request.PathBase and Request.Path values.</param>
    /// <returns>The alternative path to check alongside the unchanged path.</returns>
    public static string NormalizeSeparators(string path)
    {
        var separators = path.Replace("%2F", "/", StringComparison.OrdinalIgnoreCase)
            .Replace("%5C", "/", StringComparison.OrdinalIgnoreCase)
            .Replace('\\', '/');
        return RepeatedSlashes.Replace(separators, "/");
    }
}
