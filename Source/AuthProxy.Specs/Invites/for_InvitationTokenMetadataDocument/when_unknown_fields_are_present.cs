// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenMetadataDocument;

public class when_unknown_fields_are_present : given.a_metadata_document
{
    void Because() => Parse(Document.Replace("{", "{\"future\":42,", StringComparison.Ordinal));
    [Fact] void should_accept() => accepted.ShouldBeTrue();
}
