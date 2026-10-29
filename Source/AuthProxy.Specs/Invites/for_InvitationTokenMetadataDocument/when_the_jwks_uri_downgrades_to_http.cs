// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenMetadataDocument;

public class when_the_jwks_uri_downgrades_to_http : given.a_metadata_document
{
    void Because() => Parse(Document.Replace("https://", "http://", StringComparison.Ordinal));
    [Fact] void should_reject() => accepted.ShouldBeFalse();
}
