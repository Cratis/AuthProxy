// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenMetadataDocument;

public class when_a_property_is_duplicated : given.a_metadata_document
{
    void Because() => Parse(Document.Replace("{", "{\"issuer\":\"issuer\",", StringComparison.Ordinal));
    [Fact] void should_reject() => accepted.ShouldBeFalse();
}
