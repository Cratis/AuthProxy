// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

public class when_session_context_is_forwarded : given.a_recorded_session
{
    ClientPrincipal _result;
    void Because() => _result = _principal.WithSessionContext(_context);
    [Fact] void should_forward_the_recorded_start() => _result.Claims.Single(_ => _.Type == SessionClaims.Started).Value.ShouldEqual("1700000000");
    [Fact] void should_forward_the_recorded_scheme() => _result.Claims.Single(_ => _.Type == SessionClaims.SignInProvider).Value.ShouldEqual("microsoft");
    [Fact] void should_preserve_the_account_provider() => _result.AccountProvider.ShouldEqual(_principal.AccountProvider);
    [Fact] void should_not_modify_the_original_envelope() => _principal.Claims.Any(_ => SessionClaims.IsReserved(_.Type)).ShouldBeFalse();
}
