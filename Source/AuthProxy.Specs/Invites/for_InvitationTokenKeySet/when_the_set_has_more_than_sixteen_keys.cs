// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeySet;

public class when_the_set_has_more_than_sixteen_keys : given.a_key_set
{
    void Because() => Parse(Enumerable.Repeat(Key, 17).ToArray());
    [Fact] void should_reject_the_set() => Accepted.ShouldBeFalse();
}
