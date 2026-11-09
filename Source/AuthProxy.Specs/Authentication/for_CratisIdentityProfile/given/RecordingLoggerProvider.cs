// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;

namespace Cratis.AuthProxy.Authentication.for_CratisIdentityProfile.given;

/// <summary>
/// Records every formatted message, with every level enabled, from every logger the host creates.
/// </summary>
public sealed class RecordingLoggerProvider : ILoggerProvider
{
    readonly ConcurrentQueue<string> _messages = new();

    /// <summary>
    /// Gets every recorded message, including exception text, joined into a single block.
    /// </summary>
    public string Text => string.Join(Environment.NewLine, _messages);

    /// <inheritdoc/>
    public ILogger CreateLogger(string categoryName) => new Recorder(_messages);

    /// <inheritdoc/>
    public void Dispose()
    {
    }

    sealed class Recorder(ConcurrentQueue<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            messages.Enqueue($"{formatter(state, exception)} {exception}");
    }
}
