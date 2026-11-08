// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using Cratis.AuthProxy.Telemetry;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A traced bearer request continues the caller's trace through the proxy to the service, drops the caller's
/// baggage, and leaves telemetry that names only bounded outcomes: no token, claim value, account, tenant,
/// client or URL appears in any span tag or metric tag, so a telemetry backend never holds a credential.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_a_bearer_request_is_traced(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.RoutePrefix}/tools";
    const string TraceId = "0af7651916cd43dd8448eb211c80319c";
    const string Baggage = "caller-key=caller-value-9f3b";

    readonly ConcurrentQueue<string> _recordedValues = new();
    readonly ConcurrentQueue<string> _spanNames = new();
    ActivityListener? _activityListener;
    MeterListener? _meterListener;
    HttpResponseMessage? _response;
    ForwardedRequest? _forwarded;
    string _token = string.Empty;

    public async ValueTask InitializeAsync()
    {
        _activityListener = new ActivityListener
        {
            ShouldListenTo = _ => true,
            Sample = (ref _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                _spanNames.Enqueue(activity.OperationName);
                foreach (var tag in activity.TagObjects)
                {
                    _recordedValues.Enqueue(tag.Value?.ToString() ?? string.Empty);
                }

                foreach (var tag in activity.Tags)
                {
                    _recordedValues.Enqueue(tag.Value ?? string.Empty);
                }
            }
        };
        ActivitySource.AddActivityListener(_activityListener);

        _meterListener = new MeterListener
        {
            InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == WellKnownTelemetryNames.Scope)
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            }
        };
        _meterListener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            foreach (var tag in tags)
            {
                _recordedValues.Enqueue(tag.Value?.ToString() ?? string.Empty);
            }
        });
        _meterListener.Start();

        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();
        _token = harness.Issuer.Token();

        var request = BearerRouteHarness.WithToken(HttpMethod.Post, Path, _token);
        request.Headers.TryAddWithoutValidation("traceparent", $"00-{TraceId}-b7ad6b7169203331-01");
        request.Headers.TryAddWithoutValidation("baggage", Baggage);
        _response = await client.SendAsync(request);
        _forwarded = harness.Origin.LastRequestTo(Path);
    }

    public ValueTask DisposeAsync()
    {
        _activityListener?.Dispose();
        _meterListener?.Dispose();
        _response?.Dispose();
        return ValueTask.CompletedTask;
    }

    [Fact] public void should_forward_the_request() => Assert.Equal(HttpStatusCode.OK, _response!.StatusCode);
    [Fact] public void should_continue_the_callers_trace_to_the_service() => Assert.Contains(TraceId, _forwarded!.Value("traceparent"), StringComparison.Ordinal);
    [Fact] public void should_not_forward_the_callers_baggage() => Assert.False(_forwarded!.Has("baggage"));
    [Fact] public void should_record_the_bearer_validation_span() => Assert.Contains(WellKnownTelemetryNames.BearerValidateSpan, _spanNames);
    [Fact] public void should_record_something() => Assert.NotEmpty(_recordedValues);
    [Fact] public void should_not_record_the_token() => Assert.DoesNotContain(_recordedValues, value => value.Contains(_token, StringComparison.Ordinal));
    [Fact] public void should_not_record_the_baggage() => Assert.DoesNotContain(_recordedValues, value => value.Contains("caller-value-9f3b", StringComparison.Ordinal));
    [Fact] public void should_not_record_the_account() => Assert.DoesNotContain(_recordedValues, value => value.Contains(BearerRouteHarness.AccountId, StringComparison.Ordinal));
    [Fact] public void should_not_record_the_tenant() => Assert.DoesNotContain(_recordedValues, value => value.Contains(BearerRouteHarness.TenantId, StringComparison.Ordinal));
    [Fact] public void should_not_record_the_github_login() => Assert.DoesNotContain(_recordedValues, value => value.Contains(BearerRouteHarness.GitHubLogin, StringComparison.Ordinal));
    [Fact] public void should_not_record_the_client() => Assert.DoesNotContain(_recordedValues, value => value.Contains(BearerRouteHarness.ClientId, StringComparison.Ordinal));
    [Fact] public void should_record_the_validation_outcome() => Assert.Contains("succeeded", _recordedValues);
}
