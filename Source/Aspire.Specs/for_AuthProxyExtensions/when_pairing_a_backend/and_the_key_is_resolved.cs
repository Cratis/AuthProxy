// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_the_key_is_resolved : given.an_auth_proxy_and_a_backend
{
    readonly List<string> _messages = [];
    bool _loggedSecret;
    bool _formattedSecret;

    async Task Because()
    {
        _builder.Services.AddLogging(logging => logging.SetMinimumLevel(LogLevel.Trace).AddProvider(new CaptureLogs(_messages)));
        await using var services = _builder.Services.BuildServiceProvider();
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("pairing-spec");
        logger.Log(LogLevel.Information, new EventId(1), "Observing pairing", null, static (state, _) => state);
        _resource.WithBackend("main", _api).WithSignedForwardingTo(_api);
        var environment = await EnvironmentOf(_resource.Resource);
        var secret = environment[$"{SignerPrefix}__SecretBase64"];
        var raw = await RawEnvironmentOf(_resource.Resource);
        _formattedSecret = raw.Values.Any(value => (value.ToString() ?? string.Empty).Contains(secret, StringComparison.Ordinal));
        _loggedSecret = _messages.Exists(message => message.Contains(secret, StringComparison.Ordinal));
    }

    [Fact] void should_observe_the_logger() => _messages.Count.ShouldBeGreaterThan(0);
    [Fact] void should_not_log_the_key() => _loggedSecret.ShouldBeFalse();
    [Fact] void should_not_format_the_key_in_raw_environment_values() => _formattedSecret.ShouldBeFalse();

    sealed class CaptureLogs(List<string> messages) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new CaptureLogger(messages);
        public void Dispose() { }
    }

    sealed class CaptureLogger(List<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) => messages.Add(formatter(state, exception));
    }
}
