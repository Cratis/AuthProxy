// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_PostLogoutRedirectPolicy.given;

public class a_logout_request : Specification
{
    protected C.AuthProxy _config;
    protected DefaultHttpContext _context;
    protected bool _allowed;

    void Establish()
    {
        _config = new()
        {
            Services = new Dictionary<string, C.Service>
            {
                ["console"] = new() { Hosts = ["console.example.test"], Backend = new() { BaseUrl = "http://backend/" } },
                ["operations"] = new() { Hosts = ["operations.example.test"], Backend = new() { BaseUrl = "http://backend/" } }
            }
        };

        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("console.example.test");
    }

    protected void Check(string redirect) => _allowed = PostLogoutRedirectPolicy.IsAllowed(_context, _config, redirect);
}
