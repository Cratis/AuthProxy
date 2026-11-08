// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfApplication.when_preparing_a_call;

public class with_default_actor_headers : Specification
{
    const string Token = "synthetic-call-attestation";
    HttpRequestMessage _request;
    HttpRequestMessage _explicitlyDisabled;
    OnBehalfSession _session;

    void Establish()
    {
        _request = new();
        _explicitlyDisabled = new();
        _session = Sessions.At(DateTimeOffset.UtcNow);
    }

    void Because()
    {
        OnBehalfApplication.AddHeaders(_request, _session, null, Token, new C.OnBehalf().OmitActorHeaderOnBackChannelCalls);
        OnBehalfApplication.AddHeaders(_explicitlyDisabled, _session, null, Token, false);
    }

    [Fact] void should_default_to_sending_the_actor() => new C.OnBehalf().OmitActorHeaderOnBackChannelCalls.ShouldBeFalse();
    [Fact] void should_send_the_actor() => _request.Headers.GetValues(Headers.OnBehalfActor).Single().ShouldEqual(OnBehalfApplication.Describe(_session.Actor).ToBase64());
    [Fact] void should_send_the_actor_when_explicitly_disabled() => _explicitlyDisabled.Headers.GetValues(Headers.OnBehalfActor).Single().ShouldEqual(OnBehalfApplication.Describe(_session.Actor).ToBase64());
    [Fact] void should_send_the_tenant() => _request.Headers.GetValues(Headers.TenantId).Single().ShouldEqual(Sessions.Tenant);
    [Fact] void should_send_the_legacy_tenant() => _request.Headers.GetValues(Headers.LegacyTenantId).Single().ShouldEqual(Sessions.Tenant);
    [Fact] void should_send_a_bearer_attestation() => _request.Headers.Authorization!.Scheme.ShouldEqual("Bearer");
    [Fact] void should_preserve_the_exact_attestation() => _request.Headers.Authorization!.Parameter.ShouldEqual(Token);
    [Fact] void should_preserve_the_exact_attestation_when_explicitly_disabled() => _explicitlyDisabled.Headers.Authorization!.Parameter.ShouldEqual(Token);
}
