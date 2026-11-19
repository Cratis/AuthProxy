// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Ingress;

/// <summary>
/// Fails startup rather than silently dropping an unusable refusal prefix.
/// </summary>
public class DeniedPathConfigurationValidator : IValidateOptions<C.Ingress>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.Ingress options)
    {
        var failures = options.DeniedPathPrefixes
            .Select((entry, index) => (Entry: entry, Index: index))
            .Where(_ => !IsValid(_.Entry))
            .Select(_ => $"{C.Ingress.SectionKey}:{nameof(C.Ingress.DeniedPathPrefixes)}:{_.Index} must be an absolute plain ASCII path without escapes, backslashes, dot-dot, path parameters, whitespace or query/fragment delimiters.")
            .ToArray();

        return failures.Length > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }

    static bool IsValid(string? entry) =>
        !string.IsNullOrEmpty(entry)
        && entry.All(_ => _ <= 127)
        && !entry.Contains('%')
        && !entry.Contains("..", StringComparison.Ordinal)
        && DeniedPathNormalization.TryNormalize(entry, out _)
        && !entry.Contains('?');
}
