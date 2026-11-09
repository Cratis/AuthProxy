// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.given;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.when_validating;

/// <summary>A token whose payload was changed after signing is refused.</summary>
public class and_the_signature_was_tampered_with : an_upstream_access_token
{
    async Task Because()
    {
        var parts = CreateAccessToken().Split('.');
        var forged = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[1])).Replace("777", "888", StringComparison.Ordinal);
        _result = await Validate($"{parts[0]}.{Base64UrlEncoder.Encode(forged)}.{parts[2]}");
    }

    [Fact] void should_refuse_the_token() => _result.ShouldBeNull();
}
