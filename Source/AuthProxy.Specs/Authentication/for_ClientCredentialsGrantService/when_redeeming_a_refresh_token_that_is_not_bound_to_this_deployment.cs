// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsGrantService;

/// <summary>
/// A refresh token is redeemable only by the deployment and the service it was issued for. One issued by
/// another environment, an access token offered as a refresh token, and one for a service this deployment no
/// longer configures are all refused, and nothing is issued for them.
/// </summary>
public class when_redeeming_a_refresh_token_that_is_not_bound_to_this_deployment : Specification
{
    ClientCredentialsGrantResult _own;
    ClientCredentialsGrantResult _otherEnvironment;
    ClientCredentialsGrantResult _accessToken;
    ClientCredentialsGrantResult _unknownService;
    ClientCredentialsGrantResult _garbage;
    ClientCredentialsGrantResult _missing;

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

        var services = builder.Services.BuildServiceProvider();
        var protector = services.GetRequiredService<ClientCredentialsTokenProtector>();
        var resolver = services.GetRequiredService<ClientCredentialsServiceResolver>();
        var grants = services.GetRequiredService<ClientCredentialsGrantService>();
        resolver.TryResolveForTokenRequest("portal", out var service, out _).ShouldBeTrue();

        var otherEnvironment = new ClientCredentialsTokenProtector(new EphemeralDataProtectionProvider());
        var removed = new ConfiguredClientCredentialsService("removed", "/gone", new Uri("http://removed.test/verify"));

        _own = await Redeem(grants, protector.CreateRefreshToken(service, "orders-api"));
        _otherEnvironment = await Redeem(grants, otherEnvironment.CreateRefreshToken(service, "orders-api"));
        _accessToken = await Redeem(grants, protector.CreateToken(service, "orders-api"));
        _unknownService = await Redeem(grants, protector.CreateRefreshToken(removed, "orders-api"));
        _garbage = await Redeem(grants, "not-a-token");
        _missing = await Redeem(grants, "  ");
    }

    [Fact] void should_issue_tokens_for_its_own_refresh_token() => _own.Succeeded.ShouldBeTrue();
    [Fact] void should_refuse_a_refresh_token_from_another_environment() => _otherEnvironment.Succeeded.ShouldBeFalse();
    [Fact] void should_answer_another_environment_as_an_invalid_grant() => _otherEnvironment.Error.ShouldEqual("invalid_grant");
    [Fact] void should_refuse_an_access_token_offered_as_a_refresh_token() => _accessToken.Succeeded.ShouldBeFalse();
    [Fact] void should_answer_an_access_token_as_an_invalid_grant() => _accessToken.Error.ShouldEqual("invalid_grant");
    [Fact] void should_refuse_a_refresh_token_for_a_service_no_longer_configured() => _unknownService.Succeeded.ShouldBeFalse();
    [Fact] void should_answer_an_unknown_service_as_an_invalid_grant() => _unknownService.Error.ShouldEqual("invalid_grant");
    [Fact] void should_refuse_garbage() => _garbage.Succeeded.ShouldBeFalse();
    [Fact] void should_refuse_a_blank_refresh_token() => _missing.Succeeded.ShouldBeFalse();
    [Fact] void should_issue_no_token_to_a_refused_redemption() => new[] { _otherEnvironment, _accessToken, _unknownService, _garbage, _missing }.Where(result => result.AccessToken.Length > 0 || result.RefreshToken.Length > 0).ShouldBeEmpty();

    static Task<ClientCredentialsGrantResult> Redeem(ClientCredentialsGrantService grants, string token) =>
        grants.GrantAsync(ClientCredentialsDefaults.RefreshGrantType, null, null, null, token, CancellationToken.None);
}
