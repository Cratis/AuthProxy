// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_a_signed_deployment_discovers_a_plain_http_token_endpoint : given.user_access_tokens
{
    UserAccessTokenResult _result;

    void Establish()
    {
        _configuration.CurrentValue.Returns(new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service> { ["app"] = new() { Backend = new() { BaseUrl = "https://app.example" }, ForwardedIdentity = new() } }
        });
        _options.Configuration!.TokenEndpoint = "http://localhost/token";
        _httpClientFactory.ClearReceivedCalls();
    }

    async Task Because() => _result = await Get();

    [Fact] void should_report_the_provider_unavailable() => _result.Failure.ShouldEqual(UserAccessTokenFailure.ProviderUnavailable);
    [Fact] void should_log_the_transport_decision() => _logger.Text.ShouldContain("requires HTTPS");
    [Fact] void should_not_log_the_token_endpoint() => _logger.Text.ShouldNotContain("http://localhost/token");
    [Fact] void should_not_send_a_token_request() => _endpoint.Received.ShouldBeEmpty();
    [Fact] void should_not_create_a_client() => _httpClientFactory.DidNotReceive().CreateClient(Arg.Any<string>());
}
