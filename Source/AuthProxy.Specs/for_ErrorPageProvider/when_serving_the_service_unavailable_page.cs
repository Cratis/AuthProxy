// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.for_ErrorPageProvider;

public class when_serving_the_service_unavailable_page : Specification
{
    ErrorPageProvider _provider;
    DefaultHttpContext _context;
    string _html;

    void Establish()
    {
        var environment = Substitute.For<IWebHostEnvironment>();
        environment.ContentRootPath.Returns(AppContext.BaseDirectory);
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy());
        _provider = new ErrorPageProvider(environment, config);
        _context = new DefaultHttpContext();
        _context.Response.Body = new MemoryStream();
    }

    async Task Because()
    {
        await _provider.WriteErrorPageAsync(_context, WellKnownPageNames.ServiceUnavailable, StatusCodes.Status503ServiceUnavailable);
        _html = Encoding.UTF8.GetString(((MemoryStream)_context.Response.Body).ToArray());
    }

    [Fact] void should_respond_with_service_unavailable() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_serve_html() => _context.Response.ContentType.ShouldEqual("text/html; charset=utf-8");
    [Fact] void should_show_the_service_unavailable_heading() => _html.ShouldContain("<h1>Service unavailable</h1>");
    [Fact] void should_explain_that_organization_information_is_temporarily_unavailable() => _html.ShouldContain("Your organization information is temporarily unavailable. Please try again in a moment.");
    [Fact] void should_not_claim_the_user_has_no_organization() => _html.ShouldNotContain("your account is not associated with any organization");
}
