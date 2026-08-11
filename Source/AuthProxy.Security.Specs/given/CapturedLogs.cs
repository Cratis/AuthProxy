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
/// Normally specs stay away from logging, and for good reason — it is presentation, and asserting on it makes
/// specs brittle. This is the exception the rule leaves room for: a warning is the entire user-visible
/// behavior of the compatibility fallback. A deployment that has not declared its trusted proxies is not
/// refused, is not degraded, and behaves exactly as before; the one thing that tells its operator anything at
/// all is the line at startup. A spec that skipped it would be leaving the feature's only observable effect
/// unverified.
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
