// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_PostLogoutRedirectPolicy;

public class when_the_target_has_another_scheme : given.a_logout_request
{
    void Because() => Check("javascript:alert(1)");

    [Fact] void should_not_allow_it() => _allowed.ShouldBeFalse();
}
