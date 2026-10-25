// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeySet;

public class when_a_key_has_symmetric_key_material : given.a_key_set
{
    void Establish() => Key["k"] = "private";
    void Because() => Parse(CreateKey("other"), Key);
    [Fact] void should_reject_the_whole_set() => Accepted.ShouldBeFalse();
}
