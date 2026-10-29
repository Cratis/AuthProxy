// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeySet;

public class when_a_key_has_no_kid : given.a_key_set
{
    void Establish() => Key.Remove("kid");
    void Because() => Parse(Key);
    [Fact] void should_parse() => Accepted.ShouldBeTrue();
    [Fact] void should_skip_the_key() => Keys.Count.ShouldEqual(0);
}
