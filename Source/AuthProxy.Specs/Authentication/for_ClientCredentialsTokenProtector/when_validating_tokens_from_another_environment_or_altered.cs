// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsTokenProtector;

/// <summary>
/// A token is bound to the key ring of the deployment that issued it: one from another environment, one with a
/// character changed, and one cut short are all refused, as access and as refresh tokens.
/// </summary>
public class when_validating_tokens_from_another_environment_or_altered : given.a_client_credentials_token_protector
{
    ClientCredentialsTokenProtector _otherEnvironment;
    string _accessToken;
    string _refreshToken;
    string _otherAccessToken;
    string _otherRefreshToken;

    void Establish()
    {
        _otherEnvironment = new ClientCredentialsTokenProtector(new EphemeralDataProtectionProvider(), Time);
        _accessToken = Protector.CreateToken(Service, "orders-api");
        _refreshToken = Protector.CreateRefreshToken(Service, "orders-api");
        _otherAccessToken = _otherEnvironment.CreateToken(Service, "orders-api");
        _otherRefreshToken = _otherEnvironment.CreateRefreshToken(Service, "orders-api");
    }

    [Fact] void should_accept_its_own_access_token() => Protector.TryValidate(_accessToken, out _).ShouldBeTrue();
    [Fact] void should_accept_its_own_refresh_token() => Protector.TryValidateRefreshToken(_refreshToken, out _).ShouldBeTrue();
    [Fact] void should_refuse_an_access_token_issued_in_another_environment() => Protector.TryValidate(_otherAccessToken, out _).ShouldBeFalse();
    [Fact] void should_refuse_a_refresh_token_issued_in_another_environment() => Protector.TryValidateRefreshToken(_otherRefreshToken, out _).ShouldBeFalse();
    [Fact] void should_refuse_an_access_token_with_a_changed_character() => Protector.TryValidate(Alter(_accessToken), out _).ShouldBeFalse();
    [Fact] void should_refuse_a_refresh_token_with_a_changed_character() => Protector.TryValidateRefreshToken(Alter(_refreshToken), out _).ShouldBeFalse();
    [Fact] void should_refuse_a_truncated_access_token() => Protector.TryValidate(_accessToken[..(_accessToken.Length / 2)], out _).ShouldBeFalse();
    [Fact] void should_refuse_a_truncated_refresh_token() => Protector.TryValidateRefreshToken(_refreshToken[..(_refreshToken.Length / 2)], out _).ShouldBeFalse();
    [Fact] void should_refuse_an_empty_access_token() => Protector.TryValidate(string.Empty, out _).ShouldBeFalse();
    [Fact] void should_refuse_an_empty_refresh_token() => Protector.TryValidateRefreshToken(string.Empty, out _).ShouldBeFalse();

    static string Alter(string token)
    {
        var index = token.Length / 2;
        return token[..index] + (token[index] == 'A' ? 'B' : 'A') + token[(index + 1)..];
    }
}
