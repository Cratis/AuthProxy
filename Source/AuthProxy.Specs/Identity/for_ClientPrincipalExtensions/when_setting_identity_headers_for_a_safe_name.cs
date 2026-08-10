// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

/// <summary>
/// A safe name is written exactly as it always was, and any sibling header left behind by an earlier
/// caller is removed rather than left to contradict it. A stale <c>x-ms-client-principal-name*</c> would
/// tell a backend the plain header is encoded when it is not, which is a name change by omission.
/// </summary>
public class when_setting_identity_headers_for_a_safe_name : Specification
{
    const string Name = "user@example.com";

    DefaultHttpContext _context;
    ClientPrincipal _principal;

    void Establish()
    {
        _context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("oid", "user-42"),
                new Claim("email", Name)
            ],
            "aad"))
        };
        _principal = _context.BuildClientPrincipal()!;
        _context.Request.Headers[Headers.PrincipalNameExtended] = "UTF-8''stale";
    }

    void Because() => _context.Request.SetMicrosoftIdentityHeaders(_principal);

    [Fact] void should_send_the_name_byte_identically() =>
        _context.Request.Headers[Headers.PrincipalName].ToString().ShouldEqual(Name);

    [Fact] void should_send_the_principal_id_byte_identically() =>
        _context.Request.Headers[Headers.PrincipalId].ToString().ShouldEqual("user-42");

    [Fact] void should_not_send_a_sibling_header() =>
        _context.Request.Headers.ContainsKey(Headers.PrincipalNameExtended).ShouldBeFalse();
}
