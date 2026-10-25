// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenMetadataDocument;

public class when_the_document_is_not_json : given.a_metadata_document
{
    void Because() => Parse("not json");
    [Fact] void should_reject() => accepted.ShouldBeFalse();
}
