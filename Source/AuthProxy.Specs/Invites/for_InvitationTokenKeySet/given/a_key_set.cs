// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeySet.given;

public class a_key_set : Specification
{
    protected Dictionary<string, object> Key;
    protected bool Accepted;
    protected IReadOnlyDictionary<string, SecurityKey> Keys;

    void Establish() => Key = CreateKey("first");

    protected static Dictionary<string, object> CreateKey(string kid, int bits = 2048)
    {
        using var rsa = RSA.Create(bits);
        var parameters = rsa.ExportParameters(false);
        return new() { ["kty"] = "RSA", ["use"] = "sig", ["alg"] = "RS256", ["kid"] = kid, ["n"] = Base64UrlEncoder.Encode(parameters.Modulus), ["e"] = Base64UrlEncoder.Encode(parameters.Exponent) };
    }

    protected void Parse(params Dictionary<string, object>[] keys) => ParseJson(JsonSerializer.Serialize(new { keys }));
    protected void ParseJson(string json) => Accepted = InvitationTokenKeySet.TryParse(Encoding.UTF8.GetBytes(json), out Keys, out _);
}
