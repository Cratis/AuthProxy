// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityBody;

/// <summary>
/// A body over the bound is refused, and — the part that matters — the bytes beyond it are never read.
/// </summary>
public class when_the_body_exceeds_the_bound : Specification
{
    const int Bound = 128;

    given.CountingStream _body;
    string? _read;

    void Establish() => _body = new given.CountingStream(Bound * 100);

    async Task Because() => _read = await CapabilityBody.TryRead(_body, Bound, CancellationToken.None);

    void Destroy() => _body.Dispose();

    [Fact] void should_refuse_the_capability() => _read.ShouldBeNull();
    [Fact] void should_not_read_past_the_bound() => _body.BytesRead.ShouldBeLessThan(Bound + 65);
}
