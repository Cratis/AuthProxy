// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.Identity.for_InjectIdentityHeadersTransform;

public class when_the_request_selects_a_service : Specification
{
    RequestTransformContext _current;
    RequestTransformContext _legacy;
    RequestTransformContext _conflicting;
    RequestTransformContext _query;
    RequestTransformContext _none;

    void Establish()
    {
        _current = ContextFor("portal", null);
        _legacy = ContextFor(null, "portal");
        _conflicting = ContextFor("portal", "other");
        _query = ContextFor(null, null);
        _query.HttpContext.Request.QueryString = new QueryString("?service=portal");
        _none = ContextFor(null, null);
    }

    async Task Because()
    {
        var transform = new InjectIdentityHeadersTransform();
        foreach (var context in new[] { _current, _legacy, _conflicting, _query, _none })
        {
            await transform.ApplyAsync(context);
        }
    }

    [Fact] void should_forward_the_current_selection_under_both_names() => ShouldForwardBoth(_current);
    [Fact] void should_forward_the_legacy_selection_under_both_names() => ShouldForwardBoth(_legacy);
    [Fact] void should_forward_the_winning_current_selection_under_both_names() => ShouldForwardBoth(_conflicting);
    [Fact] void should_forward_the_query_selection_under_both_names() => ShouldForwardBoth(_query);
    [Fact] void should_not_invent_a_current_service_header() => _none.ProxyRequest.Headers.Contains(Headers.ServiceId).ShouldBeFalse();
    [Fact] void should_not_invent_a_legacy_service_header() => _none.ProxyRequest.Headers.Contains(Headers.LegacyServiceId).ShouldBeFalse();

    static void ShouldForwardBoth(RequestTransformContext context)
    {
        context.ProxyRequest.Headers.GetValues(Headers.ServiceId).Single().ShouldEqual("portal");
        context.ProxyRequest.Headers.GetValues(Headers.LegacyServiceId).Single().ShouldEqual("portal");
    }

    static RequestTransformContext ContextFor(string? current, string? legacy)
    {
        var context = new RequestTransformContext
        {
            HttpContext = new DefaultHttpContext(),
            ProxyRequest = new HttpRequestMessage(HttpMethod.Get, "https://service.local/api/test")
        };
        if (current is not null)
        {
            context.HttpContext.Request.Headers[Headers.ServiceId] = current;
            context.ProxyRequest.Headers.Add(Headers.ServiceId, current);
        }

        if (legacy is not null)
        {
            context.HttpContext.Request.Headers[Headers.LegacyServiceId] = legacy;
            context.ProxyRequest.Headers.Add(Headers.LegacyServiceId, legacy);
        }

        return context;
    }
}
