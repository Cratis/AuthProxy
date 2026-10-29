// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Tenancy.for_SelectedTenantCookie.given;

public class a_selected_tenant_cookie : Specification
{
    protected SelectedTenantCookie _cookie;

    void Establish() => _cookie = new SelectedTenantCookie(new EphemeralDataProtectionProvider());

    protected static DefaultHttpContext SignedInAs(string oid)
    {
        return new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", oid)], "aad"))
        };
    }

    protected static DefaultHttpContext RequestCarrying(DefaultHttpContext responder, string oid)
    {
        var header = responder.Response.Headers.SetCookie.ToString();
        var start = header.IndexOf($"{Cookies.Tenant}=", StringComparison.Ordinal);
        var request = SignedInAs(oid);
        request.Request.Headers.Cookie = header[start..header.IndexOf(';', start)];
        return request;
    }
}
