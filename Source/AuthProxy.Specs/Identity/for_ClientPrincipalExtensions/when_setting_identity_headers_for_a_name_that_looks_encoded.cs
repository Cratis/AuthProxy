// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

/// <summary>
/// The sibling header's presence is the whole contract a backend is told to read, so it has to be present
/// for every value the plain header carries in encoded form — including one the person chose to make look
/// encoded. Without it, a name beginning with the charset prefix was forwarded verbatim and unannounced,
/// which is the one case where "no sibling" and "decode on the prefix" disagree, and disagree in favor of
/// the caller.
/// </summary>
public class when_setting_identity_headers_for_a_name_that_looks_encoded : Specification
{
    const string Name = "UTF-8''victim%0D%0AX-Admin:%20true";

    DefaultHttpContext _context;
    ClientPrincipal _principal;
    string _decodedName;

    void Establish()
    {
        _context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("oid", "user-42"),
                new Claim("name", Name)
            ],
            "aad"))
        };
        _principal = _context.BuildClientPrincipal()!;
    }

    void Because()
    {
        _context.Request.SetMicrosoftIdentityHeaders(_principal);
        HeaderValue.TryDecode(_context.Request.Headers[Headers.PrincipalName].ToString(), out _decodedName);
    }

    [Fact] void should_announce_the_encoding_with_the_sibling_header() =>
        _context.Request.Headers.ContainsKey(Headers.PrincipalNameExtended).ShouldBeTrue();

    [Fact] void should_not_forward_the_name_verbatim() =>
        _context.Request.Headers[Headers.PrincipalName].ToString().ShouldNotEqual(Name);

    [Fact] void should_carry_the_same_value_on_both_headers() =>
        _context.Request.Headers[Headers.PrincipalNameExtended].ToString()
            .ShouldEqual(_context.Request.Headers[Headers.PrincipalName].ToString());

    [Fact] void should_decode_back_to_the_exact_name() =>
        string.Equals(_decodedName, Name, StringComparison.Ordinal).ShouldBeTrue();

    [Fact] void should_not_let_a_line_break_reach_the_consumer() =>
        _decodedName.Any(character => character is '\r' or '\n').ShouldBeFalse();

    [Fact] void should_keep_the_exact_name_in_the_client_principal() =>
        string.Equals(_principal.UserDetails, Name, StringComparison.Ordinal).ShouldBeTrue();
}
