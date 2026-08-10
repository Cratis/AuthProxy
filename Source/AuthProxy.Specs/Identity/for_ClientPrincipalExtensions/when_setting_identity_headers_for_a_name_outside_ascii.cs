// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

/// <summary>
/// The <see cref="HttpRequest"/> overload has to encode exactly like the outgoing-message one — a value
/// that is safe on one path and unencoded on the other is how a backend ends up with two different answers
/// to who the caller is.
/// </summary>
public class when_setting_identity_headers_for_a_name_outside_ascii : Specification
{
    const string Name = "Ольга Иванова";

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
        HeaderValue.TryDecode(_context.Request.Headers[Headers.PrincipalNameExtended].ToString(), out _decodedName);
    }

    [Fact] void should_send_the_name_as_an_extended_value() =>
        _context.Request.Headers[Headers.PrincipalName].ToString().ShouldEqual(HeaderValue.ToTransportValue(Name));

    [Fact] void should_send_only_printable_ascii_on_the_name_header() =>
        _context.Request.Headers[Headers.PrincipalName].ToString().Any(character => character is < ' ' or > '~').ShouldBeFalse();

    [Fact] void should_announce_the_encoding_with_the_sibling_header() =>
        _context.Request.Headers.ContainsKey(Headers.PrincipalNameExtended).ShouldBeTrue();

    [Fact] void should_decode_the_sibling_back_to_the_exact_name() =>
        string.Equals(_decodedName, Name, StringComparison.Ordinal).ShouldBeTrue();

    [Fact] void should_keep_the_exact_name_in_the_client_principal() =>
        string.Equals(_principal.UserDetails, Name, StringComparison.Ordinal).ShouldBeTrue();
}
