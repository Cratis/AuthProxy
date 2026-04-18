// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_jwt_bearer_is_configured : Specification
{
    IEnumerable<AuthenticationScheme> _schemes;

    async Task Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Authentication.SectionKey}:JwtBearer:Authority"] = "https://issuer.example",
            [$"{C.Authentication.SectionKey}:JwtBearer:Audience"] = "authproxy"
        });

        builder.AddIngressAuthentication();

        var serviceProvider = builder.Services.BuildServiceProvider();
        var schemeProvider = serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
        _schemes = await schemeProvider.GetAllSchemesAsync();
    }

    [Fact]
    void should_register_the_jwt_bearer_scheme() =>
        _schemes.Any(_ => _.Name == JwtBearerDefaults.AuthenticationScheme).ShouldBeTrue();
}
