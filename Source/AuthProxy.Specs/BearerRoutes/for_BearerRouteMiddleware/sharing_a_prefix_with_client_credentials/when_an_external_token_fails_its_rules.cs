// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware.sharing_a_prefix_with_client_credentials;

public class when_an_external_token_fails_its_rules : given.a_bearer_route_sharing_its_prefix_with_client_credentials
{
    DefaultHttpContext _context = default!;

    async Task Because()
    {
        _context = Request($"{Prefix}/orders", $"Bearer {InvalidExternalToken}");
        await Middleware.InvokeAsync(_context);
    }

    [Fact] void should_refuse_it() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_name_the_resource_metadata() => Challenge(_context).ShouldContain($"resource_metadata=\"{ResourceMetadataUrl}\"");
    [Fact] void should_validate_it_once_as_a_bearer_token() => Validator.ReceivedCalls().Count().ShouldEqual(1);
    [Fact] void should_not_retry_it_under_client_credentials() => Next.ReceivedCalls().ShouldBeEmpty();
}
