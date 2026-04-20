// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.ErrorPages.for_ErrorPageProvider;

public class when_page_has_relative_assets : Specification
{
    ErrorPageProvider _provider;
    DefaultHttpContext _context;
    string _rootDirectory;

    void Establish()
    {
        _rootDirectory = Path.Combine(Path.GetTempPath(), $"authproxy-pages-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_rootDirectory);
        File.WriteAllText(
            Path.Combine(_rootDirectory, "access-denied.html"),
            "<html><head><link rel=\"stylesheet\" href=\"styles.css\" /></head><body><img src=\"logo.svg\" /></body></html>");

        var config = new C.AuthProxy { PagesPath = _rootDirectory };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var environment = Substitute.For<IWebHostEnvironment>();
        environment.ContentRootPath.Returns("/tmp/not-used");

        _provider = new ErrorPageProvider(environment, optionsMonitor);

        _context = new DefaultHttpContext();
        _context.Response.Body = new MemoryStream();
    }

    async Task Because() => await _provider.WriteErrorPageAsync(_context, "access-denied.html", StatusCodes.Status403Forbidden);

    [Fact]
    void should_insert_base_href_before_relative_assets_are_declared()
    {
        _context.Response.Body.Position = 0;
        using var reader = new StreamReader(_context.Response.Body);
        var body = reader.ReadToEnd();

        var baseIndex = body.IndexOf("<base href=\"/_pages/\">", StringComparison.Ordinal);
        var linkIndex = body.IndexOf("<link rel=\"stylesheet\" href=\"styles.css\" />", StringComparison.Ordinal);

        baseIndex.ShouldBeGreaterThan(-1);
        linkIndex.ShouldBeGreaterThan(-1);
        (baseIndex < linkIndex).ShouldBeTrue();
    }
}