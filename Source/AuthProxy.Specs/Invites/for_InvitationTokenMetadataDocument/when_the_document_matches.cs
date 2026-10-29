// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenMetadataDocument;

public class when_the_document_matches : given.a_metadata_document
{
    void Because() => Parse(Document);
    [Fact] void should_accept() => accepted.ShouldBeTrue();
    [Fact] void should_preserve_the_path_prefix() => jwks.AbsoluteUri.ShouldEqual("https://lobby.example.com/prefix/keys");
}
