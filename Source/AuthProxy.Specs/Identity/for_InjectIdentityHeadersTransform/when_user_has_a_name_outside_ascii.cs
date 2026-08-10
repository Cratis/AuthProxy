// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.Identity.for_InjectIdentityHeadersTransform;

/// <summary>
/// A display name is whatever the provider says it is, and providers say things like <c>Søren Wærstad</c>.
/// Such a value cannot be written to a header field at all, so before this the proxied request failed at
/// the gateway and the person could not use the application. It now travels as an RFC 8187
/// <c>ext-value</c>, announced by the starred sibling, with the exact original still in the client
/// principal.
/// </summary>
public class when_user_has_a_name_outside_ascii : Specification
{
    const string Name = "Søren Wærstad";

    InjectIdentityHeadersTransform _transform;
    RequestTransformContext _transformContext;
    string _forwardedName;
    string _forwardedExtendedName;
    ClientPrincipal? _forwardedPrincipal;
    string _decodedName;

    void Establish()
    {
        _transform = new InjectIdentityHeadersTransform();

        var httpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("oid", "user-42"),
                new Claim("name", Name)
            ],
            "aad"))
        };

        _transformContext = new RequestTransformContext
        {
            HttpContext = httpContext,
            ProxyRequest = new HttpRequestMessage(HttpMethod.Get, "https://service.local/api/test")
        };
        _transformContext.ProxyRequest.Headers.Add(Headers.PrincipalNameExtended, "hostile-extended-name");
    }

    async Task Because()
    {
        await _transform.ApplyAsync(_transformContext);

        _forwardedName = _transformContext.ProxyRequest.Headers.GetValues(Headers.PrincipalName).Single();
        _forwardedExtendedName = _transformContext.ProxyRequest.Headers.GetValues(Headers.PrincipalNameExtended).Single();
        ClientPrincipal.TryFromBase64(_transformContext.ProxyRequest.Headers.GetValues(Headers.Principal).Single(), out _forwardedPrincipal);
        HeaderValue.TryDecode(_forwardedExtendedName, out _decodedName);
    }

    [Fact] void should_still_send_the_principal_name_header() =>
        _transformContext.ProxyRequest.Headers.Contains(Headers.PrincipalName).ShouldBeTrue();

    [Fact] void should_send_the_name_as_an_extended_value() =>
        _forwardedName.ShouldEqual("UTF-8''S%C3%B8ren%20W%C3%A6rstad");

    [Fact] void should_send_only_printable_ascii_on_the_name_header() =>
        _forwardedName.Any(character => character is < ' ' or > '~').ShouldBeFalse();

    [Fact] void should_announce_the_encoding_with_the_sibling_header() =>
        _forwardedExtendedName.ShouldEqual(_forwardedName);

    [Fact] void should_replace_a_hostile_sibling_header() =>
        _forwardedExtendedName.ShouldNotEqual("hostile-extended-name");

    [Fact] void should_decode_the_sibling_back_to_the_exact_name() =>
        string.Equals(_decodedName, Name, StringComparison.Ordinal).ShouldBeTrue();

    [Fact] void should_keep_the_exact_name_in_the_client_principal() =>
        string.Equals(_forwardedPrincipal!.UserDetails, Name, StringComparison.Ordinal).ShouldBeTrue();
}
