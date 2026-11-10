// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackSender;

public class when_there_is_no_tenant_and_no_secret : given.a_sender
{
    protected override string? Tenant => null;

    protected override string Secret => string.Empty;

    JsonElement _body;

    async Task Because()
    {
        _delivered = await _sender.Send(CreateRequest(), CancellationToken.None);
        _body = JsonElement.Parse(_handler.LastRequestBody!);
    }

    [Fact] void should_send_no_secret() => _handler.LastRequest!.Headers.Contains(Headers.SignInCallbackSecret).ShouldBeFalse();
    [Fact] void should_send_no_tenant_header() => _handler.LastRequest!.Headers.Contains(Headers.TenantId).ShouldBeFalse();
    [Fact] void should_leave_the_tenant_out_of_the_body() => _body.TryGetProperty("tenant", out _).ShouldBeFalse();
}
