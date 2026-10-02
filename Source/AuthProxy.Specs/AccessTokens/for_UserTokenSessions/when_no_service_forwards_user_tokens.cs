// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenSessions;

public class when_no_service_forwards_user_tokens : given.a_sign_in_redeeming_its_code
{
    void Establish() => _config.Services["reporting"].AccessToken = null;

    Task Because() => UserTokenSessions.Capture(_context);

    [Fact] void should_keep_nothing() => _store.DidNotReceive().Create(Arg.Any<UserTokenSession>(), Arg.Any<CancellationToken>());
    [Fact] void should_leave_the_session_untouched() => _properties.Items.ContainsKey(UserTokenSessions.PropertiesKey).ShouldBeFalse();
}
