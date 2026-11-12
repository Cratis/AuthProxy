// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionLifetimePolicy;

public class when_resolving_provider_settings : Specification
{
    [Theory]
    [InlineData(null, null, 12, false)]
    [InlineData(2, null, 2, false)]
    [InlineData(24, null, 12, false)]
    [InlineData(null, true, 12, false)]
    [InlineData(null, false, 12, false)]
    public void should_only_shorten_the_global_ceiling(int? hours, bool? sliding, int effectiveHours, bool effectiveSliding)
    {
        var provider = hours is null && sliding is null ? null : new C.ProviderSession { Lifetime = hours is { } value ? TimeSpan.FromHours(value) : null, SlidingExpiration = sliding };
        var result = SessionLifetimePolicy.Resolve(new C.Session(), provider);
        result.Lifetime.ShouldEqual(TimeSpan.FromHours(effectiveHours));
        result.Sliding.ShouldEqual(effectiveSliding);
        result.IsOverride.ShouldEqual(effectiveHours < 12);
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void should_inherit_or_disable_global_sliding(bool? providerSliding, bool expected)
    {
        var result = SessionLifetimePolicy.Resolve(new C.Session { SlidingExpiration = true }, new C.ProviderSession { SlidingExpiration = providerSliding });
        result.Sliding.ShouldEqual(expected);
        result.IsOverride.ShouldEqual(providerSliding == false);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void should_use_the_existing_global_fallback(int hours) => SessionLifetimePolicy.Resolve(new C.Session { Lifetime = TimeSpan.FromHours(hours) }, new C.ProviderSession { Lifetime = TimeSpan.FromHours(20) }).Lifetime.ShouldEqual(C.Session.DefaultLifetime);

    [Fact]
    public void should_inherit_for_an_unknown_scheme()
    {
        var authentication = new C.Authentication();
        authentication.OidcProviders.Add(new C.OidcProvider { Name = "Known Provider", Session = new C.ProviderSession { Lifetime = TimeSpan.FromHours(1) } });
        SessionLifetimePolicy.Resolve(new C.Session(), authentication, "unknown").IsOverride.ShouldBeFalse();
    }

    [Fact]
    public void should_choose_the_most_restrictive_duplicate_registration()
    {
        var authentication = new C.Authentication();
        authentication.OidcProviders.Add(new C.OidcProvider { Name = "Mixed Provider", Session = new C.ProviderSession { Lifetime = TimeSpan.FromHours(1) } });
        authentication.OAuthProviders.Add(new C.OAuthProvider { Name = "mixed-provider", Session = new C.ProviderSession { Lifetime = TimeSpan.FromHours(2), SlidingExpiration = false } });
        var result = SessionLifetimePolicy.Resolve(new C.Session { SlidingExpiration = true }, authentication, "mixed-provider");
        result.Lifetime.ShouldEqual(TimeSpan.FromHours(1));
        result.Sliding.ShouldBeFalse();
    }

    [Fact]
    public void should_inherit_when_the_block_is_empty() => SessionLifetimePolicy.Resolve(new C.Session { SlidingExpiration = true }, new C.ProviderSession()).IsOverride.ShouldBeFalse();
}
