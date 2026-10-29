// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Tenancy.for_TenantVerifier;

public class when_the_tenant_identifier_is_placed_in_the_url : Specification
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

    async Task Because() => _result = await _verifier.VerifyAsync("Acme-1.2_3~x");

    [Fact] void should_be_verified() => _result.ShouldBeTrue();
    [Fact] void should_keep_allowed_punctuation_unchanged() => _calledUrl.ShouldEqual("https://verification.local/tenants/Acme-1.2_3~x");

    sealed class RecordingHandler(when_the_tenant_identifier_is_placed_in_the_url specification) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            specification._calls++;
            specification._calledUrl = request.RequestUri?.AbsoluteUri ?? string.Empty;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
