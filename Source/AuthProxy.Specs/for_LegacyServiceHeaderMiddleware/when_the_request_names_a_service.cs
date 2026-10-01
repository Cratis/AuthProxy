// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_LegacyServiceHeaderMiddleware;

/// <summary>
/// Arc names the service in <c language="text">x-cratis-microservice</c>; earlier AuthProxy releases named it in
/// <c language="text">Service-ID</c>. A client still sending the old name keeps being routed, because the middleware gives its request the
/// new header the route table matches on. When both are sent the new one wins, so route selection and the
/// service-level authorization that reads the same request cannot be pointed at two different services.
/// </summary>
public class when_the_request_names_a_service : Specification
{
    DefaultHttpContext _legacyOnly;
    DefaultHttpContext _both;
    DefaultHttpContext _currentOnly;
    DefaultHttpContext _neither;
    DefaultHttpContext _blankCurrent;
    int _reached;

    void Establish()
    {
        _legacyOnly = new DefaultHttpContext();
        _legacyOnly.Request.Headers["Service-ID"] = "portal";

        _both = new DefaultHttpContext();
        _both.Request.Headers["Service-ID"] = "legacy";
        _both.Request.Headers["x-cratis-microservice"] = "current";

        _currentOnly = new DefaultHttpContext();
        _currentOnly.Request.Headers["x-cratis-microservice"] = "current";

        _neither = new DefaultHttpContext();

        _blankCurrent = new DefaultHttpContext();
        _blankCurrent.Request.Headers["x-cratis-microservice"] = " ";
        _blankCurrent.Request.Headers["Service-ID"] = "portal";
    }

    async Task Because()
    {
        var middleware = new LegacyServiceHeaderMiddleware(_ =>
        {
            _reached++;
            return Task.CompletedTask;
        });

        foreach (var context in new[] { _legacyOnly, _both, _currentOnly, _neither, _blankCurrent })
        {
            await middleware.InvokeAsync(context);
        }
    }

    [Fact] void should_route_a_legacy_header_as_the_current_one() => _legacyOnly.Request.Headers[Headers.ServiceId].ToString().ShouldEqual("portal");
    [Fact] void should_leave_the_legacy_header_for_the_backend() => _legacyOnly.Request.Headers[Headers.LegacyServiceId].ToString().ShouldEqual("portal");
    [Fact] void should_let_the_current_header_win_over_the_legacy_one() => _both.Request.Headers[Headers.ServiceId].ToString().ShouldEqual("current");
    [Fact] void should_leave_a_current_header_alone() => _currentOnly.Request.Headers[Headers.ServiceId].ToString().ShouldEqual("current");
    [Fact] void should_add_nothing_when_no_service_is_named() => _neither.Request.Headers.ContainsKey(Headers.ServiceId).ShouldBeFalse();
    [Fact] void should_use_the_legacy_header_when_the_current_one_is_blank() => _blankCurrent.Request.Headers[Headers.ServiceId].ToString().ShouldEqual("portal");
    [Fact] void should_continue_the_pipeline_for_every_request() => _reached.ShouldEqual(5);
}
