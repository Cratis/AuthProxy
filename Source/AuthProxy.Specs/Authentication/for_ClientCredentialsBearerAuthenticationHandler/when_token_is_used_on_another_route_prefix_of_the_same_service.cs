// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsBearerAuthenticationHandler;

/// <summary>
/// A token is bound to the route prefix it was issued for, not just to the service name: replayed against the
/// other prefix of the same service it is refused, and one protected by another key ring is never trusted.
/// </summary>
public class when_token_is_used_on_another_route_prefix_of_the_same_service : Specification
{
    AuthenticateResult _sameService;
    AuthenticateResult _sameRoute;
    AuthenticateResult _otherKeyRing;

    async Task Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Services:portal:Backend:BaseUrl"] = "http://portal.test/",
            [$"{C.AuthProxy.SectionKey}:Services:portal:IdentityVerification"] = nameof(C.IdentityVerificationMode.BestEffort),
            [$"{C.AuthProxy.SectionKey}:Services:portal:ClientCredentials:RoutePrefix"] = "/api",
            [$"{C.AuthProxy.SectionKey}:Services:portal:ClientCredentials:VerificationPath"] = "/.cratis/client-credentials/verify",
        });

        builder.AddIngressConfiguration();
        builder.AddIngressAuthentication();

        var serviceProvider = builder.Services.BuildServiceProvider();
        var tokenProtector = serviceProvider.GetRequiredService<ClientCredentialsTokenProtector>();
        var resolver = serviceProvider.GetRequiredService<ClientCredentialsServiceResolver>();
        resolver.TryResolveForTokenRequest("portal", out var service, out _).ShouldBeTrue();

        var otherPrefix = new ConfiguredClientCredentialsService(service.Name, "/other", new Uri("http://portal.test/verify"));
        var otherEnvironment = new ClientCredentialsTokenProtector(new Microsoft.AspNetCore.DataProtection.EphemeralDataProtectionProvider());

        _sameService = await Authenticate(serviceProvider, tokenProtector.CreateToken(otherPrefix, "orders-api"));
        _sameRoute = await Authenticate(serviceProvider, tokenProtector.CreateToken(service, "orders-api"));
        _otherKeyRing = await Authenticate(serviceProvider, otherEnvironment.CreateToken(service, "orders-api"));
    }

    [Fact] void should_refuse_a_token_issued_for_another_prefix() => _sameService.Succeeded.ShouldBeFalse();
    [Fact] void should_report_a_failure_rather_than_no_result() => _sameService.Failure.ShouldNotBeNull();
    [Fact] void should_accept_a_token_issued_for_this_prefix() => _sameRoute.Succeeded.ShouldBeTrue();
    [Fact] void should_not_authenticate_a_token_from_another_key_ring() => _otherKeyRing.Succeeded.ShouldBeFalse();
    [Fact] void should_not_even_fail_a_token_from_another_key_ring_so_that_other_schemes_may_judge_it() => _otherKeyRing.None.ShouldBeTrue();

    static async Task<AuthenticateResult> Authenticate(IServiceProvider services, string token)
    {
        // The authentication handler is cached per scope, so each request needs a scope of its own.
        await using var scope = services.CreateAsyncScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Path = "/api/orders";
        context.Request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token).ToString();
        return await context.AuthenticateAsync(ClientCredentialsDefaults.AuthenticationScheme);
    }
}
