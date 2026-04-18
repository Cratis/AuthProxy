// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_TenantVerifier;

public class when_verification_call_throws : Specification
{
    TenantVerifier _verifier;
    bool _result;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            TenantVerification = new C.TenantVerification
            {
                UrlTemplate = "https://verification.local/tenants/{tenantId}"
            }
        };

        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(
            new HttpClient(new ThrowingHttpMessageHandler()));

        _verifier = new TenantVerifier(
            optionsMonitor,
            httpClientFactory,
            Substitute.For<ILogger<TenantVerifier>>());
    }

    async Task Because() => _result = await _verifier.VerifyAsync(Guid.NewGuid());

    [Fact] void should_not_be_verified() => _result.ShouldBeFalse();

    class ThrowingHttpMessageHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("Simulated verification failure");
    }
}
