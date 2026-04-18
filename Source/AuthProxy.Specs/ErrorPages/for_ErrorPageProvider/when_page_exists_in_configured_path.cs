// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.ErrorPages.for_ErrorPageProvider;

public class when_page_exists_in_configured_path : Specification
{
    ErrorPageProvider _provider;
    DefaultHttpContext _context;
    string _rootDirectory;

    void Establish()
    {
        _rootDirectory = Path.Combine(Path.GetTempPath(), $"authproxy-pages-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_rootDirectory);
        File.WriteAllText(Path.Combine(_rootDirectory, "access-denied.html"), "<html><body>Configured Page</body></html>");

        var config = new C.AuthProxy { PagesPath = _rootDirectory };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var environment = Substitute.For<IWebHostEnvironment>();
        environment.ContentRootPath.Returns("/tmp/not-used");

        _provider = new ErrorPageProvider(environment, optionsMonitor);

        _context = new DefaultHttpContext();
        _context.Response.Body = new MemoryStream();
    }

    Task Because() => _provider.WriteErrorPageAsync(_context, "access-denied.html", StatusCodes.Status403Forbidden);

    [Fact] void should_set_status_code() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);

    [Fact]
    void should_write_the_configured_page_contents()
    {
        _context.Response.Body.Position = 0;
        using var reader = new StreamReader(_context.Response.Body);
        var body = reader.ReadToEnd();
        body.ShouldContain("Configured Page");
    }
}
