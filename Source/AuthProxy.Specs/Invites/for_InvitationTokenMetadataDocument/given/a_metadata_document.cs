// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.Invites.for_InvitationTokenMetadataDocument.given;

public class a_metadata_document : Specification
{
    protected const string Document = """{"issuer":"issuer","audience":"audience","jwks_uri":"https://lobby.example.com/prefix/keys","token_signing_alg_values_supported":["RS256"]}""";
    protected bool accepted;
    protected Uri jwks;
    protected string failure;

    protected void Parse(string json) => accepted = InvitationTokenMetadataDocument.TryParse(Encoding.UTF8.GetBytes(json), new Uri("https://lobby.example.com/metadata"), "issuer", "audience", out jwks, out failure);
}
