// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenSessions;

public class when_the_provider_issues_no_refresh_token : given.a_sign_in_redeeming_its_code
{
    void Establish() => _context.TokenEndpointResponse.RefreshToken = null;

    Task Because() => UserTokenSessions.Capture(_context);

    [Fact] void should_keep_nothing() => _store.DidNotReceive().Create(Arg.Any<UserTokenSession>(), Arg.Any<CancellationToken>());
}
