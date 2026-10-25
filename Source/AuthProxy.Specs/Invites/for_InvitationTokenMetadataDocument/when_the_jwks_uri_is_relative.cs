// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenMetadataDocument;

public class when_the_jwks_uri_is_relative : given.a_metadata_document
{
    void Because() => Parse(Document.Replace("https://lobby.example.com", string.Empty, StringComparison.Ordinal));
    [Fact] void should_reject() => accepted.ShouldBeFalse();
}
