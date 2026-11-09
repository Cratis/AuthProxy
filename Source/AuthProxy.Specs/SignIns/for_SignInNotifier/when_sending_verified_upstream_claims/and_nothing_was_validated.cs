// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_sending_verified_upstream_claims;

/// <summary>
/// No validated token means no claims — however much the caller, the request or the session principal asserts.
/// </summary>
public class and_nothing_was_validated : a_verified_claims_sign_in_notifier
{
    string _body;

    protected override ClaimsPrincipal CreatePrincipal() => new(new ClaimsIdentity(
    [
        new Claim("sub", "subject-123"),
        new Claim("iss", "https://forged.example.com"),
        new Claim("github_id", "1"),
        new Claim("idp_sub", "forged"),
    ],
    "github"));

    async Task Because()
    {
        _httpContext.Request.Headers["x-verified-claims"] = "{\"sub\":\"forged\"}";
        _httpContext.Request.Headers["github_id"] = "1";
        _httpContext.Request.Headers["x-cratis-idp-sub"] = "forged";
        _httpContext.Request.QueryString = new QueryString("?sub=forged&verifiedClaims=forged");
        await _notifier.Notify(_httpContext, _principal, Scheme);
        _body = Encoding.UTF8.GetString(_handler.LastRequestBytes.Span);
    }

    [Fact] void should_still_notify() => _handler.LastRequest.ShouldNotBeNull();
    [Fact] void should_send_no_verified_claims() => _body.Contains("verifiedClaims").ShouldBeFalse();
    [Fact] void should_not_forward_a_caller_supplied_value() => (_body.Contains("idp_sub") || _body.Contains("github_id") || _body.Contains("x-verified-claims")).ShouldBeFalse();
}
