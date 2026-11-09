// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace Cratis.AuthProxy.Security.Telemetry.for_TelemetryExport;

public class when_completed_spans_are_exported : given.an_export_pipeline
{
    void Because()
    {
        foreach (var kind in new[] { ActivityKind.Client, ActivityKind.Server, ActivityKind.Internal })
        {
            using var activity = Source.StartActivity("request", kind)!;
            activity.SetTag("server.address", SensitiveValue)
                .SetTag("server.port", 443)
                .SetTag("url.full", SensitiveUrl)
                .SetTag("http.url", SensitiveUrl)
                .SetTag("http.host", SensitiveValue)
                .SetTag("net.peer.name", SensitiveValue)
                .SetTag("url.query", "code=private-code")
                .SetTag("url.path", "/invite/private-token")
                .SetTag("http.request.method", "GET")
                .SetTag("exception.message", SensitiveUrl)
                .SetStatus(ActivityStatusCode.Error, SensitiveUrl)
                .AddException(new HttpRequestException(SensitiveUrl))
                .AddEvent(new ActivityEvent("diagnostic", tags: new ActivityTagsCollection
                {
                    ["exception.stacktrace"] = SensitiveUrl,
                    ["outcome"] = "failed"
                }));
        }
    }

    [Fact] public void should_export_every_activity_kind() => Assert.Equal(3, Activities.Count);
    [Fact] public void should_clear_full_urls_on_every_activity() => Assert.All(Activities, activity => Assert.Null(activity.GetTagItem("url.full")));
    [Fact] public void should_clear_legacy_full_urls() => Assert.All(Activities, activity => Assert.Null(activity.GetTagItem("http.url")));
    [Fact] public void should_clear_hosts_on_every_activity() => Assert.All(Activities, activity => Assert.Null(activity.GetTagItem("server.address")));
    [Fact] public void should_clear_client_host_aliases() => Assert.All(Activities.Where(activity => activity.Kind != ActivityKind.Server), activity => Assert.Null(activity.GetTagItem("net.peer.name")));
    [Fact] public void should_keep_safe_http_attributes() => Assert.All(Activities, activity => Assert.Equal("GET", activity.GetTagItem("http.request.method")));
    [Fact] public void should_clear_exception_attributes() => Assert.All(Activities, activity => Assert.Null(activity.GetTagItem("exception.message")));
    [Fact] public void should_export_the_native_exception_event_without_its_payload() => Assert.All(Activities, activity => Assert.Empty(Assert.Single(activity.Events, item => item.Name == "exception").Tags));
    [Fact] public void should_clear_exception_payloads_on_other_events() => Assert.All(Activities, activity => Assert.Equal("failed", Assert.Single(Assert.Single(activity.Events, item => item.Name == "diagnostic").Tags).Value));
    [Fact] public void should_clear_status_descriptions() => Assert.All(Activities, activity => Assert.Null(activity.StatusDescription));
    [Fact] public void should_keep_error_status() => Assert.All(Activities, activity => Assert.Equal(ActivityStatusCode.Error, activity.Status));
    [Fact] public void should_redact_invitation_paths() => Assert.Equal("/invite/{token}", Activities.Single(activity => activity.Kind == ActivityKind.Server).GetTagItem("url.path"));
}
