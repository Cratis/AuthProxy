// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.ErrorPages.for_ErrorPageProvider;

public class when_page_exists_in_default_pages_folder : Specification
{
    ErrorPageProvider _provider;
    DefaultHttpContext _context;

    void Establish()
    {
        var contentRoot = Path.Combine(Path.GetTempPath(), $"authproxy-content-{Guid.NewGuid():N}");
        var pages = Path.Combine(contentRoot, "Pages");
        Directory.CreateDirectory(pages);
        File.WriteAllText(Path.Combine(pages, "not-found.html"), "<html><body>Default Page</body></html>");

        var config = new C.AuthProxy { PagesPath = string.Empty };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var environment = Substitute.For<IWebHostEnvironment>();
        environment.ContentRootPath.Returns(contentRoot);

        _provider = new ErrorPageProvider(environment, optionsMonitor);

        _context = new DefaultHttpContext();
        _context.Response.Body = new MemoryStream();
    }

    Task Because() => _provider.WriteErrorPageAsync(_context, "not-found.html", StatusCodes.Status404NotFound);

    [Fact]
    void should_write_the_default_page_contents()
    {
        _context.Response.Body.Position = 0;
        using var reader = new StreamReader(_context.Response.Body);
        var body = reader.ReadToEnd();
        body.ShouldContain("Default Page");
    }
}
