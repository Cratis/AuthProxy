// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeySet;

public class when_use_and_alg_are_absent : given.a_key_set
{
    void Establish()
    {
        Key.Remove("use");
        Key.Remove("alg");
    }
    void Because() => Parse(Key);
    [Fact] void should_parse() => Accepted.ShouldBeTrue();
    [Fact] void should_keep_the_key() => Keys.Count.ShouldEqual(1);
}
