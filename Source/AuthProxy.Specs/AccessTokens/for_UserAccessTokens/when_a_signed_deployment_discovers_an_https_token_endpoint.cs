// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_a_signed_deployment_discovers_an_https_token_endpoint : given.user_access_tokens
{
    UserAccessTokenResult _result;

    void Establish() => _configuration.CurrentValue.Returns(new C.AuthProxy
    {
        Services = new Dictionary<string, C.Service> { ["app"] = new() { Backend = new() { BaseUrl = "https://app.example" }, ForwardedIdentity = new() } }
    });

    async Task Because() => _result = await Get();

    [Fact] void should_return_the_access_token() => _result.Succeeded.ShouldBeTrue();
    [Fact] void should_use_only_the_oidc_client() => _httpClientFactory.Received(1).CreateClient(UserAccessTokens.HttpClientName);
    [Fact] void should_not_use_the_signed_backend_client() => _httpClientFactory.DidNotReceive().CreateClient(ForwardedIdentity.ForwardedIdentityServiceCollectionExtensions.HttpClientName);
    [Fact] void should_call_the_token_endpoint() => _endpoint.Received.Count.ShouldEqual(1);
}
