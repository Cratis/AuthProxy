// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHost.given;

public class a_proxy_on_one_of_its_hosts : Specification
{
    protected C.AuthProxy _config;
    protected DefaultHttpContext _context;
    protected bool _bounced;
    protected string _location;

    void Establish()
    {
        _config = new()
        {
            Session = new() { CookieDomain = ".example.test" },
            SignIn = new() { CallbackHost = "auth.example.test" },
            Services = new Dictionary<string, C.Service>
            {
                ["console"] = new() { Hosts = ["console.example.test"], Backend = new() { BaseUrl = "http://backend/" } }
            }
        };

        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("console.example.test");
    }

    protected void BounceLogin(string returnUrl) =>
        _bounced = SignInCallbackHost.TryBuildLoginBounce(_context, _config, "github", returnUrl, out _location);

    protected void BounceLogout(string target) =>
        _bounced = SignInCallbackHost.TryBuildLogoutBounce(_context, _config, target, out _location);

    protected string QueryValue(string key) => Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri(_location).Query)[key].ToString();
}
