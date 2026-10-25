// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenMetadataDocument;

public class when_rs256_is_not_supported : given.a_metadata_document
{
    void Because() => Parse(Document.Replace("RS256", "RS512", StringComparison.Ordinal));
    [Fact] void should_reject() => accepted.ShouldBeFalse();
}
