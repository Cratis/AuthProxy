// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Diagnostics;
using Cratis.AuthProxy.Telemetry;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// With export on, the shared ASP.NET Core and HTTP client instrumentation is on too, and it records URLs. An
/// invitation token in the path, the code and state of a sign-in callback in the query, and the tenant in the
/// tenant-verification URL must not reach a span, whatever the exporter is.
/// </summary>
public class when_an_exported_request_carries_credentials_in_its_url : IAsyncLifetime
{
    const string InviteToken = "invite-token-c0ffee1234567890";
    const string CallbackCode = "callback-code-5e5e5e5e";
    const string CallbackState = "callback-state-a1a1a1a1";
    const string VerifiedTenant = "tenant-verified-7c1e";

    readonly ConcurrentQueue<Activity> _activities = new();
    TracedHarness? _harness;
    ActivityListener? _listener;

    public async ValueTask InitializeAsync()
    {
        _listener = new ActivityListener
        {
            ShouldListenTo = _ => true,
            Sample = (ref _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = _activities.Enqueue
        };
        ActivitySource.AddActivityListener(_listener);

        _harness = new TracedHarness();
        using var client = _harness.CreateBearerClient();

        using var invite = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"{WellKnownPaths.InvitePathPrefix}/{InviteToken}"), TestContext.Current.CancellationToken);
        using var callback = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"/signin-oidc?code={CallbackCode}&state={CallbackState}"), TestContext.Current.CancellationToken);

        var claims = new Dictionary<string, object> { ["tid"] = VerifiedTenant };
        using var tenantRequest = BearerRouteHarness.WithToken(HttpMethod.Get, $"{BearerRouteHarness.RoutePrefix}/tools", _harness.Issuer.Token(claims));
        using var verified = await client.SendAsync(tenantRequest, TestContext.Current.CancellationToken);

        // A span is finished after the response is, so wait for the outgoing verification call to be recorded.
        for (var attempt = 0; attempt < 50 && !_activities.Any(IsTenantVerification); attempt++)
        {
            await Task.Delay(100, TestContext.Current.CancellationToken);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _listener?.Dispose();
        if (_harness is not null)
        {
            await _harness.DisposeAsync();
        }
    }

    [Fact] public void should_record_the_incoming_request() => Assert.Contains(_activities, _ => _.Kind == ActivityKind.Server);
    [Fact] public void should_record_the_tenant_verification_call() => Assert.Contains(_activities, IsTenantVerification);
    [Fact] public void should_not_record_the_invitation_token() => Assert.DoesNotContain(Everything(_activities), value => value.Contains(InviteToken, StringComparison.Ordinal));
    [Fact] public void should_not_record_the_callback_code() => Assert.DoesNotContain(Everything(_activities), value => value.Contains(CallbackCode, StringComparison.Ordinal));
    [Fact] public void should_not_record_the_callback_state() => Assert.DoesNotContain(Everything(_activities), value => value.Contains(CallbackState, StringComparison.Ordinal));
    [Fact] public void should_not_record_the_tenant_on_the_outgoing_call() => Assert.DoesNotContain(Everything(_activities.Where(_ => _.Kind == ActivityKind.Client)), value => value.Contains(VerifiedTenant, StringComparison.Ordinal));
    [Fact] public void should_record_the_invitation_path_without_its_token() => Assert.Contains(TelemetryRedaction.RedactedInvitePath, Everything(_activities.Where(_ => _.Kind == ActivityKind.Server)));

    static bool IsTenantVerification(Activity activity) => activity.Kind == ActivityKind.Client && activity.Source.Name.Contains("Http", StringComparison.Ordinal);

    static IEnumerable<string> Everything(IEnumerable<Activity> activities) => activities.SelectMany(activity =>
        new[] { activity.OperationName, activity.DisplayName }
            .Concat(activity.TagObjects.Select(tag => tag.Value?.ToString() ?? string.Empty))
            .Concat(activity.Events.SelectMany(_ => _.Tags.Select(tag => tag.Value?.ToString() ?? string.Empty))))
        .ToArray();

    sealed class TracedHarness : BearerRouteHarness
    {
        protected override void AddSettings(IDictionary<string, string?> settings)
        {
            settings[$"{C.AuthProxy.SectionKey}:TenantVerification:UrlTemplate"] = $"{Origin.BaseUrl}/api/tenants/{{tenantId}}/exists";

            // Enables export, which enables the instrumentation; nothing listens on this port.
            settings["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://127.0.0.1:1";
        }
    }
}
