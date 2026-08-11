// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Management;

/// <summary>
/// Refuses a management section that could not produce a working private listener.
/// </summary>
/// <param name="listeners">The addresses AuthProxy already listens on.</param>
/// <remarks>
/// Every failure here has the same shape: the deployment asked for a health signal and would have got
/// something that looks like one without being one. A section with no port opens no listener, so every
/// probe against it fails to connect and the operator reads that as the application being down. A port the
/// public listener already binds publishes the endpoints to the internet, which is the opposite of what a
/// private listener is for. A path that is not rooted matches no request, so the listener exists and
/// answers the uniform not-found to its own probe.
/// <para>
/// None of those is visible in a log line, so each is named at startup — the one moment somebody is
/// watching — pointing at the exact configuration key that is wrong.
/// </para>
/// </remarks>
public class ManagementConfigurationValidator(ListenerAddresses listeners) : IValidateOptions<C.AuthProxy>
{
    /// <summary>
    /// The configuration section the management listener is declared in.
    /// </summary>
    public const string SectionKey = $"{C.AuthProxy.SectionKey}:{nameof(C.AuthProxy.Management)}";

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        if (options.Management is null)
        {
            return ValidateOptionsResult.Success;
        }

        var failures = new List<string>();

        AddFailureForPort(options.Management, failures);
        AddFailureForUnrootedPath(options.Management.LivePath, nameof(C.Management.LivePath), failures);
        AddFailureForUnrootedPath(options.Management.ReadyPath, nameof(C.Management.ReadyPath), failures);

        if (string.IsNullOrWhiteSpace(options.Management.BindAddress))
        {
            failures.Add($"{SectionKey}:{nameof(C.Management.BindAddress)} must name an address. Leave it unset for the loopback default of 127.0.0.1.");
        }

        if (string.Equals(options.Management.LivePath, options.Management.ReadyPath, StringComparison.OrdinalIgnoreCase))
        {
            failures.Add($"{SectionKey}:{nameof(C.Management.LivePath)} and {SectionKey}:{nameof(C.Management.ReadyPath)} name the same path '{options.Management.LivePath}', so one of the two answers would never be reachable.");
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }

    static void AddFailureForUnrootedPath(string path, string key, List<string> failures)
    {
        if (!path.StartsWith('/'))
        {
            failures.Add($"{SectionKey}:{key} is '{path}', which is not a rooted path. It has to start with '/' to match anything.");
        }
    }

    void AddFailureForPort(C.Management management, List<string> failures)
    {
        if (management.Port is null)
        {
            failures.Add($"{SectionKey}:{nameof(C.Management.Port)} must name the port the management listener binds. There is no default, because a port is the deployment's own decision.");
            return;
        }

        if (management.Port is < 1 or > 65535)
        {
            failures.Add($"{SectionKey}:{nameof(C.Management.Port)} is {management.Port}, which is not a port number.");
            return;
        }

        if (listeners.Uses(management.Port.Value))
        {
            failures.Add($"{SectionKey}:{nameof(C.Management.Port)} is {management.Port}, which AuthProxy already serves the public listener on. The management endpoints would then be answered to every caller the proxy is reachable from.");
        }
    }
}
