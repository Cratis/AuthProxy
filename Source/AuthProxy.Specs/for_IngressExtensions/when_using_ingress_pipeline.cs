// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ReverseProxy;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.for_IngressExtensions;

public class when_using_ingress_pipeline : Specification
{
    WebApplication _app;
    WebApplication _result;

    void Establish()
    {
        var pagesDirectory = Path.Combine(Path.GetTempPath(), $"authproxy-pages-{Guid.NewGuid():N}");
        Directory.CreateDirectory(pagesDirectory);
        var webRootDirectory = Path.Combine(Path.GetTempPath(), $"authproxy-webroot-{Guid.NewGuid():N}");
        Directory.CreateDirectory(webRootDirectory);
        File.WriteAllText(Path.Combine(webRootDirectory, "index.html"), "<html><body>Login</body></html>");

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            WebRootPath = webRootDirectory
        });
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:PagesPath"] = pagesDirectory,
            [$"{C.AuthProxy.SectionKey}:Services:Catalog:Backend:BaseUrl"] = "https://catalog-backend.local/",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Microsoft"
        });

        builder.AddIngressConfiguration();
        builder.SetupReverseProxy();

        _app = builder.Build();
    }

    void Because() => _result = _app.UseIngress();

    [Fact]
    void should_return_the_same_application_for_chaining() =>
        ReferenceEquals(_app, _result).ShouldBeTrue();
}
