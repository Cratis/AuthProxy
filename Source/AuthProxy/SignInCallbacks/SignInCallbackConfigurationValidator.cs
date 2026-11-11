// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.SignInCallbacks;

/// <summary>
/// Rejects a service's sign-in callback that could not work, so a misconfiguration fails at startup rather than silently.
/// </summary>
sealed class SignInCallbackConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <summary>
    /// The longest time a callback may wait for a service to answer.
    /// </summary>
    internal static readonly TimeSpan MaximumTimeout = TimeSpan.FromMinutes(1);

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        List<string> failures = [];
        foreach (var (serviceName, service) in options.Services)
        {
            if (service.SignInCallback is not { } callback)
            {
                continue;
            }

            var section = $"Services:{serviceName}:SignInCallback";
            if (service.Backend is null)
            {
                failures.Add($"{section} needs the service to declare a Backend, because the callback is posted to it.");
            }

            if (!IsAbsolutePath(callback.Path))
            {
                failures.Add($"{section}:Path must be an absolute path on the service's backend, such as /.cratis/showrunner/sign-in; it must start with a single '/' and carry no host, query or fragment.");
            }

            if (callback.Interval <= TimeSpan.Zero)
            {
                failures.Add($"{section}:Interval must be greater than zero.");
            }

            if (callback.Timeout <= TimeSpan.Zero || callback.Timeout > MaximumTimeout)
            {
                failures.Add($"{section}:Timeout must be greater than zero and at most {MaximumTimeout}.");
            }

            if (callback.Secret.Any(char.IsControl))
            {
                failures.Add($"{section}:Secret must not contain control characters, because it is sent as a header value.");
            }
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static bool IsAbsolutePath(string path) =>
        !string.IsNullOrWhiteSpace(path)
        && path.StartsWith('/')
        && !path.StartsWith("//", StringComparison.Ordinal)
        && !path.Contains('\\')
        && !path.Contains('?')
        && !path.Contains('#')
        && !path.Any(c => char.IsWhiteSpace(c) || char.IsControl(c));
}
