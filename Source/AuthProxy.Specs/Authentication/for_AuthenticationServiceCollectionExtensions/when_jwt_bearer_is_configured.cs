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
    ServiceProvider _services;
    JwtBearerOptions _options;

    async Task Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Authentication.SectionKey}:JwtBearer:Authority"] = "https://issuer.example",
            [$"{C.Authentication.SectionKey}:JwtBearer:Audience"] = "authproxy"
        });

        builder.AddIngressAuthentication();

        _services = builder.Services.BuildServiceProvider();
        _options = _services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);
        var schemeProvider = _services.GetRequiredService<IAuthenticationSchemeProvider>();
        _schemes = await schemeProvider.GetAllSchemesAsync();
    }

    [Fact]
    void should_register_the_jwt_bearer_scheme() =>
        _schemes.Any(_ => _.Name == JwtBearerDefaults.AuthenticationScheme).ShouldBeTrue();

    [Theory]
    [InlineData("cnf", "{\"jkt\":\"synthetic-key\"}")]
    [InlineData("cnf", "{\"x5t#S256\":\"synthetic-certificate\"}")]
    [InlineData("cnf", "{\"jwk\":{}}")]
    [InlineData("cnf", "synthetic-binding")]
    [InlineData("cnf", "{invalid-json")]
    [InlineData("Cnf", "{\"jkt\":\"synthetic-key\"}")]
    public async Task should_fail_validation_for_any_confirmation_claim(string name, string value)
    {
        var context = new TokenValidatedContext(
            new DefaultHttpContext { RequestServices = _services },
            new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, null, typeof(JwtBearerHandler)),
            _options)
        {
            Principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(name, value)], JwtBearerDefaults.AuthenticationScheme)),
        };

        await _options.Events.TokenValidated(context);

        context.Result.ShouldNotBeNull();
        context.Result!.Succeeded.ShouldBeFalse();
        context.Result.Failure!.Message.ShouldEqual("Sender-constrained access tokens are not supported.");
    }
}
