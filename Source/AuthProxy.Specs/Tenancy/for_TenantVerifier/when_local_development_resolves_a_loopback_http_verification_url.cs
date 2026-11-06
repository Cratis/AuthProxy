// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.Tenancy.for_TenantVerifier;

public class when_local_development_resolves_a_loopback_http_verification_url : Specification
{
    TenantVerifier _verifier;
    RespondingHttpMessageHandler _handler;
    bool _result;

    void Establish()
    {
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(new C.AuthProxy
        {
            Profile = C.DeploymentProfile.LocalDevelopment,
            Services = new Dictionary<string, C.Service> { ["app"] = new() { Backend = new() { BaseUrl = "https://app.example" }, ForwardedIdentity = new() } }
        });
        _handler = new(HttpStatusCode.OK);
        _verifier = new(options, _handler.AsFactory(), Substitute.For<ILogger<TenantVerifier>>());
    }

    async Task Because() => _result = await _verifier.VerifyAsync("tenant", "http://localhost/tenants/{tenantId}");

    [Fact] void should_verify_the_tenant() => _result.ShouldBeTrue();
    [Fact] void should_call_the_verifier() => _handler.Calls.ShouldEqual(1);
}
