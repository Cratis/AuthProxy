// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_reporting_v2_readiness : Specification
{
    [Fact]
    public void should_distinguish_configuration_from_an_operational_context_producer()
    {
        var config = Configuration();
        var rows = ForwardedIdentitySigningReport.For(config);
        var v2 = rows.Single(row => row.Flow == ForwardedIdentityFlow.ProxiedRequest && row.ServiceName == "v2-app");
        Assert.True(v2.IsSigned);
        Assert.Equal("v2", v2.Version);
        Assert.Equal("browser-session-only", v2.State);
        var v1 = rows.Single(row => row.Flow == ForwardedIdentityFlow.ProxiedRequest && row.ServiceName == "v1-app");
        Assert.Equal("v1", v1.Version);
        Assert.Equal("signed", v1.State);
    }

    [Fact]
    public async Task should_log_v2_refusal_instead_of_claiming_that_it_is_signed()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(Configuration());
        var logger = new StartupLogger();
        await new ForwardedIdentitySigningStartupReport(monitor, logger).StartAsync(CancellationToken.None);
        var messages = logger.Messages;
        Assert.Contains(messages, message => message.Contains("v2-app: v2, browser-session-only", StringComparison.Ordinal));
        Assert.DoesNotContain(messages, message => message.Contains("v2-app: signed", StringComparison.Ordinal));
    }

    static C.AuthProxy Configuration() => new()
    {
        Services = new Dictionary<string, C.Service>
        {
            ["v2-app"] = new() { Backend = new() { BaseUrl = "https://v2.example/" }, ForwardedIdentity = new() { Version = "v2", Audience = "backend", KeyId = "v2-key" } },
            ["v1-app"] = new() { Backend = new() { BaseUrl = "https://v1.example/" }, ForwardedIdentity = new() { Audience = "backend", KeyId = "v1-key" } }
        }
    };

    sealed class StartupLogger : ILogger<ForwardedIdentitySigningStartupReport>
    {
        public List<string> Messages { get; } = [];
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) => Messages.Add(formatter(state, exception));
    }
}
