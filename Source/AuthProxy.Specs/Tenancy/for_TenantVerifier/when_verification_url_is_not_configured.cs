// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_TenantVerifier;

public class when_verification_url_is_not_configured : Specification
{
    TenantVerifier _verifier;
    IHttpClientFactory _httpClientFactory;
    bool _result;

    void Establish()
    {
        var config = new C.AuthProxy();
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        _httpClientFactory = Substitute.For<IHttpClientFactory>();

        _verifier = new TenantVerifier(
            optionsMonitor,
            _httpClientFactory,
            Substitute.For<ILogger<TenantVerifier>>());
    }

    async Task Because() => _result = await _verifier.VerifyAsync(Guid.NewGuid().ToString());

    [Fact] void should_be_verified() => _result.ShouldBeTrue();
    [Fact] void should_not_call_http_client() => _httpClientFactory.DidNotReceive().CreateClient(Arg.Any<string>());
}
