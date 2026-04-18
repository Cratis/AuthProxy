// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_OidcProviderScheme;

public class when_converting_oauth_provider_config_to_provider_info : Specification
{
    OidcProviderInfo _providerInfo;

    void Establish()
    {
        var provider = new C.OAuthProvider
        {
            Name = "GitHub Enterprise",
            Type = C.OidcProviderType.GitHub
        };

        _providerInfo = OidcProviderScheme.ToProviderInfo(provider);
    }

    [Fact] void should_preserve_name() => _providerInfo.Name.ShouldEqual("GitHub Enterprise");
    [Fact] void should_preserve_type() => _providerInfo.Type.ShouldEqual(C.OidcProviderType.GitHub);
    [Fact] void should_compute_login_url_using_derived_scheme() => _providerInfo.LoginUrl.ShouldEqual("/.cratis/login/github-enterprise");
}
