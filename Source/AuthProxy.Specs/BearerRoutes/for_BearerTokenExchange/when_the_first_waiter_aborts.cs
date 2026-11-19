// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.for_BearerTokenExchange.given;
using Cratis.AuthProxy.BearerRoutes.TokenExchange;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerTokenExchange;

public class when_the_first_waiter_aborts
{
    [Fact]
    public async Task should_complete_the_shared_exchange_for_the_second_waiter()
    {
        var request = new ExchangeRequest();
        request.Configuration.Timeout = TimeSpan.FromSeconds(10);
        using var aborted = new CancellationTokenSource();
        request.Context.RequestAborted = aborted.Token;
        var completion = new TaskCompletionSource<TokenExchangeResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var flightToken = CancellationToken.None;
        request.Client.Exchange(Arg.Any<C.BearerTokenExchange>(), Arg.Any<C.BearerTokenExchangeIssuer>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                flightToken = call.ArgAt<CancellationToken>(4);
                return completion.Task.WaitAsync(flightToken);
            });
        var secondContext = new DefaultHttpContext();
        secondContext.Response.Body = new MemoryStream();
        secondContext.Request.Headers.Authorization = request.Context.Request.Headers.Authorization;
        request.Resolver.ResolveEach(secondContext).Returns([new TenantResolutionResult("tenant-a", C.TenantSourceIdentifierResolverType.Host)]);
        using var secondAborted = new CancellationTokenSource();
        secondContext.RequestAborted = secondAborted.Token;
        var first = request.Exchange.Prepare(request.Context, request.Resolved);
        var second = request.Exchange.Prepare(secondContext, request.Resolved);
        await aborted.CancelAsync();
        (await first.WaitAsync(TestContext.Current.CancellationToken)).ShouldBeFalse();
        flightToken.CanBeCanceled.ShouldBeTrue();
        flightToken.IsCancellationRequested.ShouldBeFalse();
        flightToken.Equals(secondAborted.Token).ShouldBeFalse();
        var token = ExchangeRequest.Jwt(request.Configuration.ResultIssuer);
        completion.SetResult(new(TokenExchangeVerdict.Success, token, 300));
        (await second.WaitAsync(TestContext.Current.CancellationToken)).ShouldBeTrue();
        secondContext.Request.Headers.Authorization.ToString().ShouldEqual("Bearer " + token);
        request.Exchange.Confirm(secondContext, request.Resolved, request.Validation()).ShouldBeTrue();
        await request.Client.Received(1).Exchange(request.Configuration, request.Configuration.Issuers[0], Arg.Any<string>(), "tenant-a", Arg.Any<CancellationToken>());
    }
}
