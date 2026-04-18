// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_OidcProviderScheme;

public class when_converting_provider_config_to_provider_info : Specification
{
    C.OidcProvider _config;
    OidcProviderInfo _result;

    void Establish() => _config = new C.OidcProvider
    {
        Name = "GitHub",
        Type = C.OidcProviderType.GitHub,
        Authority = "https://github.com",
        ClientId = "client-id",
    };

    void Because() => _result = OidcProviderScheme.ToProviderInfo(_config);

    [Fact] void should_have_correct_name() => Assert.Equal("GitHub", _result.Name);
    [Fact] void should_have_correct_type() => Assert.Equal(C.OidcProviderType.GitHub, _result.Type);
    [Fact] void should_have_login_url_with_scheme() => Assert.Equal("/.cratis/login/github", _result.LoginUrl);
}
