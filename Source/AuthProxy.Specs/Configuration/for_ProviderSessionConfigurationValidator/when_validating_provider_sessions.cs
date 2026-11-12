// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Configuration.for_ProviderSessionConfigurationValidator;

public class when_validating_provider_sessions : Specification
{
    [Theory]
    [InlineData(0, false)]
    [InlineData(-1, false)]
    [InlineData(2, true)]
    [InlineData(12, true)]
    [InlineData(13, false)]
    public void should_validate_both_provider_kinds(int hours, bool accepted)
    {
        foreach (var oidc in new[] { true, false })
        {
            var provider = new ProviderSession { Lifetime = TimeSpan.FromHours(hours) };
            var config = new AuthProxy();
            if (oidc) config.Authentication.OidcProviders.Add(new OidcProvider { Name = "oidc", Session = provider });
            else config.Authentication.OAuthProviders.Add(new OAuthProvider { Name = "oauth", Session = provider });
            var result = new ProviderSessionConfigurationValidator().Validate(null, config);
            result.Succeeded.ShouldEqual(accepted);
            if (!accepted)
            {
                result.FailureMessage.ShouldContain($"Provider '{(oidc ? "oidc" : "oauth")}'");
                result.FailureMessage.ShouldContain($"'{TimeSpan.FromHours(hours):c}'");
                result.FailureMessage.ShouldContain("The effective global Cratis:AuthProxy:Session:Lifetime ceiling is '12:00:00'");
                result.FailureMessage.ShouldContain($"Cratis:AuthProxy:Authentication:{(oidc ? "OidcProviders" : "OAuthProviders")}[0]:Session:Lifetime");
                result.FailureMessage.ShouldContain(hours <= 0 ? "must be greater than 00:00:00" : "exceeds the global session lifetime");
                result.FailureMessage.ShouldContain("Set it to a value above 00:00:00 and no longer than '12:00:00', or remove the provider's Session:Lifetime to inherit the global value.");
            }
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void should_validate_against_the_global_fallback(int globalHours)
    {
        var config = new AuthProxy { Session = new Session { Lifetime = TimeSpan.FromHours(globalHours) } };
        config.Authentication.OidcProviders.Add(new OidcProvider { Name = "work", Session = new ProviderSession { Lifetime = TimeSpan.FromHours(13) } });
        var result = new ProviderSessionConfigurationValidator().Validate(null, config);
        result.Failed.ShouldBeTrue();
        result.FailureMessage.ShouldContain("'13:00:00' exceeds the global session lifetime");
        result.FailureMessage.ShouldContain("The effective global Cratis:AuthProxy:Session:Lifetime ceiling is '12:00:00'");
        result.FailureMessage.ShouldContain("Cratis:AuthProxy:Authentication:OidcProviders[0]:Session:Lifetime");
    }

    [Fact]
    public void should_bind_null_inheritance_and_explicit_false()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["OidcProviders:0:Name"] = "oidc",
            ["OidcProviders:0:Session:Lifetime"] = "02:00:00",
            ["OAuthProviders:0:Name"] = "oauth",
            ["OAuthProviders:0:Session:SlidingExpiration"] = "false"
        }).Build().Get<Authentication>()!;
        configuration.OidcProviders[0].Session!.Lifetime.ShouldEqual(TimeSpan.FromHours(2));
        configuration.OidcProviders[0].Session!.SlidingExpiration.ShouldBeNull();
        configuration.OAuthProviders[0].Session!.Lifetime.ShouldBeNull();
        configuration.OAuthProviders[0].Session!.SlidingExpiration.ShouldEqual(false);
    }

    [Fact]
    public void should_accept_absent_and_empty_blocks_and_nullable_fields()
    {
        var config = new AuthProxy();
        config.Authentication.OidcProviders.Add(new OidcProvider());
        config.Authentication.OAuthProviders.Add(new OAuthProvider { Session = new ProviderSession { SlidingExpiration = true } });
        new ProviderSessionConfigurationValidator().Validate(null, config).Succeeded.ShouldBeTrue();
    }
}
