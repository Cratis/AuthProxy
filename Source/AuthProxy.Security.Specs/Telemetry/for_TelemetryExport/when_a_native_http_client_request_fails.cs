// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace Cratis.AuthProxy.Security.Telemetry.for_TelemetryExport;

public class when_a_native_http_client_request_fails : given.an_export_pipeline
{
    Activity _request;

    async Task Because()
    {
        using var parent = Source.StartActivity("parent");
        using var client = new HttpClient(new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectCallback = (_, _) => throw new HttpRequestException(SensitiveUrl)
        });
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(SensitiveUrl));
        _request = Assert.Single(Activities, activity => activity.Source.Name == "System.Net.Http");
    }

    [Fact] public void should_keep_the_client_span() => Assert.Equal(ActivityKind.Client, _request.Kind);
    [Fact] public void should_keep_the_http_method() => Assert.Equal("GET", _request.GetTagItem("http.request.method"));
    [Fact] public void should_keep_the_error_status() => Assert.Equal(ActivityStatusCode.Error, _request.Status);
    [Fact] public void should_export_native_exception_events_without_payloads() => Assert.Empty(Assert.Single(_request.Events, activityEvent => activityEvent.Name == "exception").Tags);
    [Fact] public void should_not_export_the_destination_host() => Assert.Null(_request.GetTagItem("server.address"));
    [Fact] public void should_not_export_the_full_url() => Assert.Null(_request.GetTagItem("url.full"));
    [Fact] public void should_not_export_a_sensitive_status_description() => Assert.Null(_request.StatusDescription);
}
