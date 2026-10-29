// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Tenancy.for_TenantVerifier;

public class when_the_tenant_identifier_is_not_usable : Specification
{
    TenantVerifier _verifier;
    bool _result;
    int _calls;
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
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(new HttpClient(new RecordingHandler(this)));

        _verifier = new TenantVerifier(optionsMonitor, httpClientFactory, Substitute.For<ILogger<TenantVerifier>>());
    }

    async Task Because() => _result = await _verifier.VerifyAsync("a/../b?x=1");

    [Fact] void should_not_be_verified() => _result.ShouldBeFalse();
    [Fact] void should_not_send_a_request() => _calls.ShouldEqual(0);

    sealed class RecordingHandler(when_the_tenant_identifier_is_not_usable specification) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            specification._calls++;
            specification._calledUrl = request.RequestUri?.AbsoluteUri ?? string.Empty;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
