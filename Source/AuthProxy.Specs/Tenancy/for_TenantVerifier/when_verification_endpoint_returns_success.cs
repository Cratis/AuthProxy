// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Tenancy.for_TenantVerifier;

public class when_verification_endpoint_returns_success : Specification
{
    const string TenantId = "11111111-1111-1111-1111-111111111111";

    TenantVerifier _verifier;
    bool _result;
    string _calledUrl = string.Empty;

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
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(new HttpClient(new RecordingHttpMessageHandler(url => _calledUrl = url, HttpStatusCode.OK)));

        _verifier = new TenantVerifier(
            optionsMonitor,
            httpClientFactory,
            Substitute.For<ILogger<TenantVerifier>>());
    }

    async Task Because() => _result = await _verifier.VerifyAsync(TenantId);

    [Fact] void should_be_verified() => _result.ShouldBeTrue();
    [Fact] void should_replace_tenant_id_in_url() => _calledUrl.ShouldContain(TenantId);

    class RecordingHttpMessageHandler(Action<string> onRequest, HttpStatusCode statusCode) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            onRequest(request.RequestUri?.ToString() ?? string.Empty);
            return Task.FromResult(new HttpResponseMessage(statusCode));
        }
    }
}
