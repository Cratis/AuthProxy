// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.given;

namespace Cratis.AuthProxy.Tenancy.for_TenantVerifier;

public class when_a_signed_deployment_resolves_a_plain_http_verification_url : Specification
{
    TenantVerifier _verifier;
    RecordingLogger<TenantVerifier> _logger;
    IHttpClientFactory _factory;
    bool _result;

    void Establish()
    {
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service> { ["app"] = new() { Backend = new() { BaseUrl = "https://app.example" }, ForwardedIdentity = new() } }
        });
        _factory = Substitute.For<IHttpClientFactory>();
        _logger = new RecordingLogger<TenantVerifier>();
        _verifier = new(options, _factory, _logger);
    }

    async Task Because() => _result = await _verifier.VerifyAsync("tenant", "http://localhost/tenants/{tenantId}");

    [Fact] void should_log_the_transport_decision() => _logger.Text.ShouldContain("requires HTTPS");
    [Fact] void should_not_log_the_verifier_url() => _logger.Text.ShouldNotContain("http://localhost/tenants/");
    [Fact] void should_not_verify_the_tenant() => _result.ShouldBeFalse();
    [Fact] void should_not_create_a_client() => _factory.DidNotReceive().CreateClient(Arg.Any<string>());
}
