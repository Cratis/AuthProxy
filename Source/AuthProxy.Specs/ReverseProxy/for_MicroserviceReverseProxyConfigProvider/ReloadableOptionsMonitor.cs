// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

/// <summary>
/// An <see cref="IOptionsMonitor{TOptions}"/> that can replace the configuration it serves, so a spec can
/// drive a reload the way a file-backed configuration source does — a new instance handed out, and every
/// registered listener notified.
/// </summary>
/// <param name="initial">The configuration to serve until the first reload.</param>
public class ReloadableOptionsMonitor(C.AuthProxy initial) : IOptionsMonitor<C.AuthProxy>
{
    readonly List<Action<C.AuthProxy, string?>> _listeners = [];

    /// <inheritdoc/>
    public C.AuthProxy CurrentValue { get; private set; } = initial;

    /// <inheritdoc/>
    public C.AuthProxy Get(string? name) => CurrentValue;

    /// <inheritdoc/>
    public IDisposable? OnChange(Action<C.AuthProxy, string?> listener)
    {
        _listeners.Add(listener);

        // The real monitor returns a registration to unsubscribe with; nothing here needs to.
        return null;
    }

    /// <summary>
    /// Serves a new configuration and notifies every listener, as a reload does.
    /// </summary>
    /// <param name="next">The configuration to serve from now on.</param>
    public void Reload(C.AuthProxy next)
    {
        CurrentValue = next;

        foreach (var listener in _listeners)
        {
            listener(next, Options.DefaultName);
        }
    }
}
