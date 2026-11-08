// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// With export on, the shared setup also exports logs, with their scopes. The hosting scope of a request carries its
/// path and the hosting diagnostics write the path and the query, so an invitation token and a callback's code and
/// state must not reach an exported log record, and the HTTP client metrics must not name the host they called.
/// </summary>
public class when_an_exported_request_is_logged : IAsyncLifetime
{
    const string InviteToken = "invite-token-c0ffee1234567890";
    const string CallbackCode = "callback-code-5e5e5e5e";
    const string CallbackState = "callback-state-a1a1a1a1";
    const string VerifiedTenant = "tenant-verified-7c1e";

    readonly ConcurrentQueue<string> _logs = new();
    readonly ConcurrentQueue<(string Name, string Tags)> _metrics = new();
    LoggedHarness? _harness;

    public async ValueTask InitializeAsync()
    {
        _harness = new LoggedHarness(_logs, _metrics);
        using var client = _harness.CreateBearerClient();

        using var invite = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"{WellKnownPaths.InvitePathPrefix}/{InviteToken}"), TestContext.Current.CancellationToken);
        using var callback = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"/signin-oidc?code={CallbackCode}&state={CallbackState}"), TestContext.Current.CancellationToken);

        var claims = new Dictionary<string, object> { ["tid"] = VerifiedTenant };
        using var tenantRequest = BearerRouteHarness.WithToken(HttpMethod.Get, $"{BearerRouteHarness.RoutePrefix}/tools", _harness.Issuer.Token(claims));
        using var verified = await client.SendAsync(tenantRequest, TestContext.Current.CancellationToken);

        for (var attempt = 0; attempt < 50 && !HasHttpClientMetric(); attempt++)
        {
            _harness.Services.GetRequiredService<MeterProvider>().ForceFlush();
            await Task.Delay(100, TestContext.Current.CancellationToken);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_harness is not null)
        {
            await _harness.DisposeAsync();
        }
    }

    [Fact] public void should_export_log_records() => Assert.NotEmpty(_logs);
    [Fact] public void should_not_export_the_invitation_token() => Assert.DoesNotContain(_logs, _ => _.Contains(InviteToken, StringComparison.Ordinal));
    [Fact] public void should_not_export_the_callback_code() => Assert.DoesNotContain(_logs, _ => _.Contains(CallbackCode, StringComparison.Ordinal));
    [Fact] public void should_not_export_the_callback_state() => Assert.DoesNotContain(_logs, _ => _.Contains(CallbackState, StringComparison.Ordinal));
    [Fact] public void should_not_export_the_tenant() => Assert.DoesNotContain(_logs, _ => _.Contains(VerifiedTenant, StringComparison.Ordinal));
    [Fact] public void should_export_http_client_metrics() => Assert.True(HasHttpClientMetric());
    [Fact] public void should_not_tag_http_client_metrics_with_the_host() => Assert.DoesNotContain(HttpClientMetrics(), _ => _.Tags.Contains("server.address", StringComparison.Ordinal) || _.Tags.Contains("dns.question.name", StringComparison.Ordinal));

    bool HasHttpClientMetric() => HttpClientMetrics().Any();

    IEnumerable<(string Name, string Tags)> HttpClientMetrics() => _metrics.Where(_ => _.Name.StartsWith("http.client.", StringComparison.Ordinal));

    sealed class LoggedHarness(ConcurrentQueue<string> logs, ConcurrentQueue<(string Name, string Tags)> metrics) : BearerRouteHarness
    {
        protected override void AddSettings(IDictionary<string, string?> settings)
        {
            settings[$"{C.AuthProxy.SectionKey}:TenantVerification:UrlTemplate"] = $"{Origin.BaseUrl}/api/tenants/{{tenantId}}/exists";
            settings["Logging:LogLevel:Default"] = "Debug";
            settings["Logging:LogLevel:Microsoft"] = "Information";

            // Enables export; nothing listens on this port.
            settings["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://127.0.0.1:1";
        }

        protected override void ConfigureHost(IWebHostBuilder builder) =>
            builder.ConfigureTestServices(services =>
            {
                services.ConfigureOpenTelemetryLoggerProvider(provider => provider.AddProcessor(new CapturingLogProcessor(logs)));
                services.ConfigureOpenTelemetryMeterProvider(provider => provider.AddReader(new BaseExportingMetricReader(new CapturingMetricExporter(metrics))));
            });
    }

    sealed class CapturingLogProcessor(ConcurrentQueue<string> logs) : BaseProcessor<LogRecord>
    {
        public override void OnEnd(LogRecord data)
        {
            var parts = new List<string> { data.CategoryName ?? string.Empty, data.Body ?? string.Empty, data.FormattedMessage ?? string.Empty };
            parts.AddRange((data.Attributes ?? []).Select(_ => $"{_.Key}={_.Value}"));
            data.ForEachScope(
                (scope, state) =>
                {
                    foreach (var item in scope)
                    {
                        state.Add($"{item.Key}={item.Value}");
                    }
                },
                parts);
            logs.Enqueue(string.Join('\n', parts));
        }
    }

    sealed class CapturingMetricExporter(ConcurrentQueue<(string Name, string Tags)> metrics) : BaseExporter<Metric>
    {
        public override ExportResult Export(in Batch<Metric> batch)
        {
            foreach (var metric in batch)
            {
                foreach (var point in metric.GetMetricPoints())
                {
                    var tags = new List<string>();
                    foreach (var tag in point.Tags)
                    {
                        tags.Add($"{tag.Key}={tag.Value}");
                    }

                    metrics.Enqueue((metric.Name, string.Join(',', tags)));
                }
            }

            return ExportResult.Success;
        }
    }
}
