// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.when_checking_a_grant;

public class and_the_service_has_forwarded_identity_signing : given.a_grant_check
{
    protected override string Body => LiveAnswer();

    void Establish() => _configuration.Value.Services[OnBehalfConfiguration.ServiceName].ForwardedIdentity = new();

    async Task Because() => await Check();

    [Fact] void should_keep_the_grant_available() => _result.Status.ShouldEqual(OnBehalfGrantStatus.Live);
    [Fact] void should_send_the_per_call_attestation() => _handler.LastAuthorization!.StartsWith("Bearer ", StringComparison.Ordinal).ShouldBeTrue();
    [Fact] void should_not_send_a_header_envelope() => _handler.LastHeaders.ContainsKey("x-cratis-forwarded-identity-signature").ShouldBeFalse();
}
