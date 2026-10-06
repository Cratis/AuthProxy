// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.ErrorPages.for_ErrorPageProvider.given;

public class an_invitation_page : Specification
{
    protected ErrorPageProvider _provider;
    protected DefaultHttpContext _context;
    string _directory;

    void Establish()
    {
        _directory = Path.Combine(Path.GetTempPath(), $"authproxy-invitation-pages-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_directory);
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(new C.AuthProxy { PagesPath = _directory });
        var environment = Substitute.For<IWebHostEnvironment>();
        environment.ContentRootPath.Returns(_directory);
        _provider = new(environment, options);
        _context = new DefaultHttpContext();
        _context.Response.Body = new MemoryStream();
    }

    protected void GivenTemplate(string html) => File.WriteAllText(Path.Combine(_directory, WellKnownPageNames.InvitationEmailMismatch), html);

    protected string Body()
    {
        _context.Response.Body.Position = 0;
        using var reader = new StreamReader(_context.Response.Body, leaveOpen: true);
        return reader.ReadToEnd();
    }

    void Destroy()
    {
        _context.Response.Body.Dispose();
        Directory.Delete(_directory, recursive: true);
    }
}
