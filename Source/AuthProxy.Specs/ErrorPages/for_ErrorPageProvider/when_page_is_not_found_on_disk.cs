// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.ErrorPages.for_ErrorPageProvider;

public class when_page_is_not_found_on_disk : Specification
{
    ErrorPageProvider _provider;
    DefaultHttpContext _context;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            PagesPath = "/tmp/path-that-does-not-exist"
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var environment = Substitute.For<IWebHostEnvironment>();
        environment.ContentRootPath.Returns("/tmp/another-path-that-does-not-exist");

        _provider = new ErrorPageProvider(environment, optionsMonitor);

        _context = new DefaultHttpContext();
        _context.Response.Body = new MemoryStream();
    }

    Task Because() => _provider.WriteErrorPageAsync(_context, "missing-page.html", StatusCodes.Status404NotFound);

    [Fact] void should_set_status_code() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status404NotFound);

    [Fact] void should_write_fallback_html()
    {
        _context.Response.Body.Position = 0;
        using var reader = new StreamReader(_context.Response.Body);
        var body = reader.ReadToEnd();
        body.ShouldContain("Error 404");
    }
}
