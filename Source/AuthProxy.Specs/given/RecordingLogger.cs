// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.given;

/// <summary>
/// Records formatted log messages while keeping every log level enabled.
/// </summary>
/// <typeparam name="TCategoryName">The logger category.</typeparam>
/// <remarks>
/// A source-generated <c>[LoggerMessage]</c> method returns before it formats anything when
/// <see cref="ILogger.IsEnabled(LogLevel)"/> answers no, and a substituted logger answers no by default. A
/// disclosure specification written against a substituted logger therefore records nothing and passes no
/// matter what the code under test writes — it proves nothing at all. This logger keeps every level enabled
/// and captures what the formatter actually produced, so what a specification inspects is the text a real
/// sink would have received.
/// </remarks>
public sealed class RecordingLogger<TCategoryName> : ILogger<TCategoryName>
{
    readonly List<string> _messages = [];

    /// <summary>
    /// Gets the formatted messages recorded by the logger.
    /// </summary>
    public IReadOnlyList<string> Messages => _messages;

    /// <summary>
    /// Gets every recorded message joined into a single block of text.
    /// </summary>
    public string Text => string.Join(Environment.NewLine, _messages);

    /// <inheritdoc/>
    public IDisposable BeginScope<TState>(TState state)
        where TState : notnull => EmptyScope.Instance;

    /// <inheritdoc/>
    public bool IsEnabled(LogLevel logLevel) => true;

    /// <inheritdoc/>
    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter) =>
        _messages.Add(formatter(state, exception));

    sealed class EmptyScope : IDisposable
    {
        public static readonly EmptyScope Instance = new();

        public void Dispose()
        {
        }
    }
}
