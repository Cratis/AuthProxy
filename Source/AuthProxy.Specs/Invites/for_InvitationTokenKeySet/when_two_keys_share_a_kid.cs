// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeySet;

public class when_two_keys_share_a_kid : given.a_key_set
{
    void Because() => Parse(Key, CreateKey("first"), CreateKey("unique"));
    [Fact] void should_parse() => Accepted.ShouldBeTrue();
    [Fact] void should_keep_only_the_unique_key() => Keys.Keys.ShouldEqual(["unique"]);
}
