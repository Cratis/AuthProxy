// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl.given;

public class a_sign_in_request : Specification
{
    protected C.AuthProxy _config;
    protected DefaultHttpContext _context;
    protected string _result;

    void Establish()
    {
        _config = new()
        {
            Session = new() { CookieDomain = ".example.test" },
            SignIn = new() { CallbackHost = "auth.example.test" },
            Services = new Dictionary<string, C.Service>
            {
                ["console"] = new() { Hosts = ["console.example.test"], Backend = new() { BaseUrl = "http://backend/" } },
                ["operations"] = new() { Hosts = ["operations.example.test:8443"], Backend = new() { BaseUrl = "http://backend/" } }
            }
        };

        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("auth.example.test");
    }

    protected void Resolve(string returnUrl) => _result = SignInReturnUrl.Resolve(_context, _config, returnUrl);
}
