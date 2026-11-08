// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Keeps every warning and error a harness's proxy wrote, so a spec can assert on what a deployment would
/// have been told.
/// </summary>
/// <remarks>
/// Logging is part of the operator-facing behavior when no trusted proxies are configured. These captures
/// let specs check that startup and ignored-header warnings explain which settings to configure.
/// </remarks>
public sealed class CapturedLogs : ILoggerProvider
{
    readonly ConcurrentQueue<string> _messages = new();

    /// <inheritdoc/>
    public ILogger CreateLogger(string categoryName) => new Sink(_messages);

    /// <inheritdoc/>
    public void Dispose()
    {
    }

    /// <summary>
    /// Gets whether anything logged mentions all of the given fragments.
    /// </summary>
    /// <param name="fragments">The fragments that must all appear in one message.</param>
    /// <returns><see langword="true"/> when one message mentions them all; otherwise <see langword="false"/>.</returns>
    public bool Mentioning(params string[] fragments) =>
        _messages.Any(message => fragments.All(fragment => message.Contains(fragment, StringComparison.Ordinal)));

    /// <summary>
    /// Records formatted messages into the owning capture.
    /// </summary>
    /// <param name="messages">Where to record them.</param>
    sealed class Sink(ConcurrentQueue<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
            {
                messages.Enqueue(formatter(state, exception));
            }
        }
    }
}
