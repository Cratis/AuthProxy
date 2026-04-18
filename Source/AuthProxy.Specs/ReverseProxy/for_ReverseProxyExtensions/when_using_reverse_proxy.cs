// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_ReverseProxyExtensions;

public class when_using_reverse_proxy : Specification
{
    WebApplication _app;
    WebApplication _result;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Services:Catalog:Backend:BaseUrl"] = "https://catalog-backend.local/"
        });

        builder.SetupReverseProxy();
        _app = builder.Build();
    }

    void Because() => _result = _app.UseReverseProxy();

    [Fact]
    void should_return_the_same_application_for_chaining() =>
        ReferenceEquals(_app, _result).ShouldBeTrue();
}
