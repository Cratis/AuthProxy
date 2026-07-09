// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsBearerAuthenticationHandler;

public class when_token_matches_the_target_service_and_route : Specification
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
        var token = tokenProtector.CreateToken(service, "orders-api");
        context.Request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token).ToString();

        _result = await context.AuthenticateAsync(ClientCredentialsDefaults.AuthenticationScheme);
    }

    [Fact] void should_authenticate_the_request() => _result.Succeeded.ShouldBeTrue();
    [Fact] void should_expose_the_client_id_as_the_subject() => _result.Principal!.FindFirst("sub")!.Value.ShouldEqual("orders-api");
    [Fact] void should_scope_the_principal_to_the_service() => _result.Principal!.FindFirst(ClientCredentialsDefaults.ServiceClaimType)!.Value.ShouldEqual("portal");
}
