// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeySet;

public class when_the_document_has_no_keys_array : given.a_key_set
{
    void Because() => ParseJson("{}");
    [Fact] void should_reject() => Accepted.ShouldBeFalse();
}
