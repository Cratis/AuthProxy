// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityBody;

/// <summary>
/// A caller announcing an oversized body is refused on the announcement, before the body is touched at all.
/// </summary>
public class when_the_declared_length_exceeds_the_bound : Specification
{
    const int Bound = 128;

    given.CountingStream _body;
    DefaultHttpContext _context;
    string? _read;

    void Establish()
    {
        _body = new given.CountingStream(Bound * 100);
        _context = new DefaultHttpContext();
        _context.Request.Body = _body;
        _context.Request.ContentLength = Bound * 100;
    }

    async Task Because() => _read = await CapabilityBody.TryRead(_context.Request, Bound, CancellationToken.None);

    void Destroy() => _body.Dispose();

    [Fact] void should_refuse_the_capability() => _read.ShouldBeNull();
    [Fact] void should_never_touch_the_body() => _body.BytesRead.ShouldEqual(0);
}
