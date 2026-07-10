// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsBearerAuthenticationHandler;

public class when_a_refresh_token_is_used_as_an_access_token : Specification
{
    AuthenticateResult _result;

    async Task Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Services:portal:Backend:BaseUrl"] = "http://portal.test/",
            [$"{C.AuthProxy.SectionKey}:Services:portal:ClientCredentials:RoutePrefix"] = "/api",
            [$"{C.AuthProxy.SectionKey}:Services:portal:ClientCredentials:VerificationPath"] = "/.cratis/client-credentials/verify",
        });

        builder.AddIngressConfiguration();
        builder.AddIngressAuthentication();

        var serviceProvider = builder.Services.BuildServiceProvider();
        var tokenProtector = serviceProvider.GetRequiredService<ClientCredentialsTokenProtector>();
        var resolver = serviceProvider.GetRequiredService<ClientCredentialsServiceResolver>();
        resolver.TryResolveForTokenRequest("portal", out var service, out _).ShouldBeTrue();

        var context = new DefaultHttpContext { RequestServices = serviceProvider };
        context.Request.Path = "/api/orders";
        var refreshToken = tokenProtector.CreateRefreshToken(service, "orders-api");
        context.Request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", refreshToken).ToString();

        _result = await context.AuthenticateAsync(ClientCredentialsDefaults.AuthenticationScheme);
    }

    [Fact] void should_reject_the_request() => _result.Succeeded.ShouldBeFalse();
}
