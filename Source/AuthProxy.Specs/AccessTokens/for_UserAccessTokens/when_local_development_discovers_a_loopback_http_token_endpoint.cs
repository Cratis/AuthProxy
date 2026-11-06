// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_local_development_discovers_a_loopback_http_token_endpoint : given.user_access_tokens
{
    UserAccessTokenResult _result;

    void Establish()
    {
        _configuration.CurrentValue.Returns(new C.AuthProxy
        {
            Profile = C.DeploymentProfile.LocalDevelopment,
            Services = new Dictionary<string, C.Service> { ["app"] = new() { Backend = new() { BaseUrl = "https://app.example" }, ForwardedIdentity = new() } }
        });
        _options.Configuration!.TokenEndpoint = "http://localhost/token";
    }

    async Task Because() => _result = await Get();

    [Fact] void should_return_the_access_token() => _result.Succeeded.ShouldBeTrue();
    [Fact] void should_call_the_token_endpoint() => _endpoint.Received.Count.ShouldEqual(1);
    [Fact] void should_use_the_oidc_client() => _httpClientFactory.Received(1).CreateClient(UserAccessTokens.HttpClientName);
}
