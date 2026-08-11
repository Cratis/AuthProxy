// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.for_UniformDenial;

/// <summary>
/// Everything an earlier decision queued on the response is gone from the refusal.
/// </summary>
/// <remarks>
/// The refusal is written after other middleware has had the request, and what those left behind is exactly
/// what would describe the deployment: a challenge header says there is something to authenticate against, a
/// <c>Location</c> names a provider, a <c>Set-Cookie</c> hands out state to a caller who presented nothing.
/// Clearing them is the difference between one refusal and a family of them.
/// <para>
/// Written as its own spec because nothing else can see the clear happen. Every spec that observes a refusal
/// observes one composed on a fresh response, where clearing an empty header collection and not clearing it
/// produce the same bytes — so the line could be deleted and the whole suite would stay green.
/// </para>
/// </remarks>
public class when_the_response_already_carries_headers : Specification
{
    DefaultHttpContext _context;
    MemoryStream _body;

    void Establish()
    {
        _body = new MemoryStream();
        _context = new DefaultHttpContext();
        _context.Request.Path = "/anything";
        _context.Response.Body = _body;
        _context.Response.Headers.WWWAuthenticate = "Bearer realm=\"members\"";
        _context.Response.Headers.Location = "https://login.example.test/authorize";
        _context.Response.Headers.SetCookie = ".cratis-tenants=eyJ0ZW5hbnRzIjpbXX0";
        _context.Response.Headers.Allow = "GET, HEAD, POST";
    }

    async Task Because() => await UniformDenial.Write(_context);

    void Destroy() => _body.Dispose();

    [Fact] void should_not_offer_a_way_to_authenticate() => _context.Response.Headers.WWWAuthenticate.Count.ShouldEqual(0);
    [Fact] void should_not_point_anywhere() => _context.Response.Headers.Location.Count.ShouldEqual(0);
    [Fact] void should_not_hand_out_state() => _context.Response.Headers.SetCookie.Count.ShouldEqual(0);
    [Fact] void should_not_name_the_methods_a_route_accepts() => _context.Response.Headers.Allow.Count.ShouldEqual(0);
    [Fact] void should_forbid_storing_the_refusal() => _context.Response.Headers.CacheControl.ToString().ShouldEqual(UniformDenial.CacheControl);
    [Fact] void should_refuse_with_the_one_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status404NotFound);
    [Fact] void should_answer_with_the_fixed_body() => Encoding.UTF8.GetString(_body.ToArray()).ShouldEqual(UniformDenial.Body);
}
