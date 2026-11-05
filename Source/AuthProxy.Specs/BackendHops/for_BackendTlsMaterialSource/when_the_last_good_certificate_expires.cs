// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsMaterialSource;

public class when_the_last_good_certificate_expires : given.a_tls_policy
{
    RecordingLogger _logger;
    BackendTlsMaterialSource _expiring;
    TimeProvider _clock;
    string _original;

    void Establish()
    {
        _logger = new();
        _clock = Substitute.For<TimeProvider>();
        _clock.GetUtcNow().Returns(DateTimeOffset.UtcNow);
        _expiring = new(monitor, _clock, _logger);
        _original = _expiring.Current.Fingerprint;
    }

    void Because()
    {
        _clock.GetUtcNow().Returns(DateTimeOffset.UtcNow.AddDays(20));
        _expiring.TryReload();
    }

    [Fact] void should_keep_the_last_good_snapshot() => _expiring.Current.Fingerprint.ShouldEqual(_original);
    [Fact] void should_log_an_error() => _logger.Levels.ShouldContain(LogLevel.Error);

    sealed class RecordingLogger : ILogger<BackendTlsMaterialSource>
    {
        public List<LogLevel> Levels { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) => Levels.Add(logLevel);
    }
}
