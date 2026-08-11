// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Microsoft.Net.Http.Headers;

namespace Cratis.AuthProxy.Management.for_ManagementEndpoints.given;

/// <summary>
/// The management endpoints over a readiness answer a spec chooses, and the response they wrote.
/// </summary>
/// <remarks>
/// The endpoints and the readiness check are held in private-protected fields because both are internal,
/// and a protected member of a public class may not be of a less accessible type.
/// </remarks>
public class a_management_endpoint : Specification
{
    protected DefaultHttpContext _context;
    protected MemoryStream _body;

    private protected StatedReadiness _readiness;
    private protected ManagementEndpoints _endpoints;

    protected virtual bool IsReady => true;

    void Establish()
    {
        _readiness = new StatedReadiness(IsReady);
        _endpoints = new ManagementEndpoints(_readiness);

        _body = new MemoryStream();
        _context = new DefaultHttpContext();
        _context.Response.Body = _body;

        // What a challenge or a session on the way out would look like, so that a response carrying either
        // is a failing spec rather than a code review someone has to remember to do.
        _context.Response.Headers[HeaderNames.WWWAuthenticate] = "Bearer";
        _context.Response.Headers[HeaderNames.SetCookie] = ".AspNetCore.Cookies=whatever";
    }

    protected string Body => Encoding.UTF8.GetString(_body.ToArray());

    void Destroy() => _body.Dispose();
}
