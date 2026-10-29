// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeySet;

public class when_a_key_names_another_algorithm : given.a_key_set
{
    void Establish() => Key["alg"] = "RS512";
    void Because() => Parse(Key);
    [Fact] void should_parse() => Accepted.ShouldBeTrue();
    [Fact] void should_skip_the_key() => Keys.Count.ShouldEqual(0);
}
