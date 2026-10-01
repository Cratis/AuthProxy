// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Refuses a configuration stating a proxy activity timeout the proxy cannot honor.
/// </summary>
/// <remarks>
/// A value below one millisecond becomes an immediate cancellation, and a value past the
/// signed integer millisecond limit YARP uses would silently shorten the configured timeout. Both are
/// configuration mistakes, so they are named here, at the one moment somebody is watching, rather than
/// surfacing as every request failing or as a silently different timeout than the one written down.
/// </remarks>
public class ActivityTimeoutConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <summary>
    /// The longest activity timeout that can be scheduled.
    /// </summary>
    internal static readonly TimeSpan Maximum = TimeSpan.FromMilliseconds(int.MaxValue);

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var failures = new List<string>();

        Check($"{C.AuthProxy.SectionKey}:{nameof(C.AuthProxy.ActivityTimeout)}", options.ActivityTimeout, failures);

        foreach (var (serviceName, service) in options.Services)
        {
            var prefix = $"{C.AuthProxy.SectionKey}:{nameof(C.AuthProxy.Services)}:{serviceName}";
            Check($"{prefix}:{nameof(C.Service.ActivityTimeout)}", service.ActivityTimeout, failures);
            Check($"{prefix}:{nameof(C.Service.Backend)}:{nameof(C.ServiceEndpoint.ActivityTimeout)}", service.Backend?.ActivityTimeout, failures);
            Check($"{prefix}:{nameof(C.Service.Frontend)}:{nameof(C.ServiceEndpoint.ActivityTimeout)}", service.Frontend?.ActivityTimeout, failures);
            if (service.Registration?.ActivityTimeout is not null)
            {
                failures.Add($"{prefix}:{nameof(C.Service.Registration)}:{nameof(C.ServiceEndpoint.ActivityTimeout)} is not supported. ActivityTimeout only applies to Backend and Frontend endpoints, not Registration. Remove this setting.");
            }
        }

        if (options.Invite?.Lobby is { } lobby)
        {
            var prefix = $"{C.AuthProxy.SectionKey}:{nameof(C.AuthProxy.Invite)}:{nameof(C.Invite.Lobby)}";
            CheckLobby($"{prefix}:{nameof(C.Service.ActivityTimeout)}", lobby.ActivityTimeout, failures);
            CheckLobby($"{prefix}:{nameof(C.Service.Backend)}:{nameof(C.ServiceEndpoint.ActivityTimeout)}", lobby.Backend?.ActivityTimeout, failures);
            CheckLobby($"{prefix}:{nameof(C.Service.Frontend)}:{nameof(C.ServiceEndpoint.ActivityTimeout)}", lobby.Frontend?.ActivityTimeout, failures);
            CheckLobby($"{prefix}:{nameof(C.Service.Registration)}:{nameof(C.ServiceEndpoint.ActivityTimeout)}", lobby.Registration?.ActivityTimeout, failures);
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }

    static void CheckLobby(string key, TimeSpan? value, List<string> failures)
    {
        if (value is not null)
        {
            failures.Add($"{key} is not supported. Invite:Lobby does not create proxy clusters, so ActivityTimeout cannot apply. Remove this setting and configure the proxied service under Services instead.");
        }
    }

    static void Check(string key, TimeSpan? value, List<string> failures)
    {
        if (value is null)
        {
            return;
        }

        if (value <= TimeSpan.Zero)
        {
            failures.Add($"{key} is '{value}', which is not greater than zero. A proxied request would be cancelled the moment it started. Leave the setting unset for the default of {C.AuthProxy.DefaultActivityTimeout}, or state how long a request may sit idle, for example '00:15:00'.");
        }
        else if (value < TimeSpan.FromMilliseconds(1))
        {
            failures.Add($"{key} is '{value}', which is less than one millisecond. The proxy would round it down to zero and cancel the request immediately. State an idle limit of at least '00:00:00.001'.");
        }
        else if (value > Maximum)
        {
            failures.Add($"{key} is '{value}', which is longer than the {Maximum} the proxy can schedule. State a shorter idle limit.");
        }
    }
}
