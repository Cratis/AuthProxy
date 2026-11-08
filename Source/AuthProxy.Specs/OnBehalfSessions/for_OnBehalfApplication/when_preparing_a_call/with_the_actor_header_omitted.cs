// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfApplication.when_preparing_a_call;

public class with_the_actor_header_omitted : Specification
{
    const string Token = "synthetic-call-attestation";
    HttpRequestMessage _request;
    OnBehalfSession _session;

    void Establish()
    {
        _request = new();
        _session = Sessions.At(DateTimeOffset.UtcNow);
    }

    void Because() => OnBehalfApplication.AddHeaders(_request, _session, null, Token, true);

    [Fact] void should_omit_the_actor() => _request.Headers.Contains(Headers.OnBehalfActor).ShouldBeFalse();
    [Fact] void should_keep_the_tenant() => _request.Headers.GetValues(Headers.TenantId).Single().ShouldEqual(Sessions.Tenant);
    [Fact] void should_keep_the_legacy_tenant() => _request.Headers.GetValues(Headers.LegacyTenantId).Single().ShouldEqual(Sessions.Tenant);
    [Fact] void should_keep_the_bearer_scheme() => _request.Headers.Authorization!.Scheme.ShouldEqual("Bearer");
    [Fact] void should_preserve_the_exact_attestation() => _request.Headers.Authorization!.Parameter.ShouldEqual(Token);
}
