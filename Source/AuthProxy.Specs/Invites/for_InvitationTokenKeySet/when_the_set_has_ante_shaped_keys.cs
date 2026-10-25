// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeySet;

public class when_the_set_has_ante_shaped_keys : given.a_key_set
{
    void Because() => Parse(Key, CreateKey("second"));
    [Fact] void should_accept() => Accepted.ShouldBeTrue();
    [Fact] void should_keep_both_keys() => Keys.Count.ShouldEqual(2);
    [Fact] void should_index_by_kid() => Keys["second"].KeyId.ShouldEqual("second");
}
