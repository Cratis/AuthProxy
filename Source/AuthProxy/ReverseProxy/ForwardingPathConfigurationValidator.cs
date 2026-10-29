// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>Validates each service's forwarding rules at startup and on options validation.</summary>
public class ForwardingPathConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var failures = new List<string>();
        foreach (var (serviceName, service) in options.Services)
        {
            Validate(serviceName, nameof(service.ForwardedPaths), service.ForwardedPaths, failures);
            Validate(serviceName, nameof(service.DeniedPaths), service.DeniedPaths, failures);
        }
        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static void Validate(string serviceName, string list, IList<C.ForwardingPathRule> rules, List<string> failures)
    {
        for (var index = 0; index < rules.Count; index++)
        {
            var rejection = ForwardingPathPolicy.Evaluate(rules[index], out _, out _);
            if (rejection != ForwardingPathEntryRejection.None)
            {
                failures.Add($"Service '{serviceName}': {list}[{index}] '{rules[index].Path}' is refused ({rejection}). Declare a rooted literal path, a valid match kind and HTTP method tokens; a root path must use Exact.");
            }
        }
    }
}
