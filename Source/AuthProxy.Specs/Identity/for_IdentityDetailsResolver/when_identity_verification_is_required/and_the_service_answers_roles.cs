// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;
using System.Text.Json;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// Pins what the identity endpoint can and cannot say. A service answers an admission verdict and details; any
/// <c language="text">roles</c> it adds are not read. The readable cookie carries the roles of the authenticated
/// session, so a frontend that gates its UI on roles the app decides reads the app's own endpoint instead.
/// </summary>
public class and_the_service_answers_roles : given.a_required_verification_resolver
{
    static readonly string[] _sessionRoles = ["reader", "anonymous", "authenticated"];

    IdentityProviderResult _result;
    JsonElement _cookie;

    void Establish() =>
        _handler.Respond = (_, _, _) => Task.FromResult(Response(
            HttpStatusCode.OK,
            /*lang=json,strict*/ "{\"isAuthenticated\":true,\"isAuthorized\":true,\"roles\":[\"app-admin\"],\"details\":{\"displayName\":\"John Doe\"}}"));

    async Task Because()
    {
        _result = await _resolver.Resolve(
            _context,
            new ClientPrincipal { UserId = "user-1", UserRoles = _sessionRoles },
            TenantId);

        var setCookie = _context.Response.Headers.SetCookie.ToString();
        var start = setCookie.IndexOf(Cookies.Identity + "=", StringComparison.Ordinal) + Cookies.Identity.Length + 1;
        var end = setCookie.IndexOf(';', start);
        var encoded = Uri.UnescapeDataString(end < 0 ? setCookie[start..] : setCookie[start..end]);
        _cookie = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(encoded))).RootElement.Clone();
    }

    [Fact] void should_return_the_roles_of_the_session() => _result.Roles.ShouldContainOnly(_sessionRoles);
    [Fact] void should_write_the_roles_of_the_session_to_the_cookie() => CookieRoles().ShouldContainOnly(_sessionRoles);
    [Fact] void should_not_write_the_roles_the_service_answered() => CookieRoles().ShouldNotContain("app-admin");

    string[] CookieRoles() =>
        _cookie.EnumerateObject()
            .First(_ => string.Equals(_.Name, "roles", StringComparison.OrdinalIgnoreCase))
            .Value.EnumerateArray().Select(_ => _.GetString()!).ToArray();
}
