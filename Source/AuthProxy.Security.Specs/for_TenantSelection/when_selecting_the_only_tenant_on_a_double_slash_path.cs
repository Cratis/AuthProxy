// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Specifications;

namespace Cratis.AuthProxy.Security.for_TenantSelection;

[Collection(TenantSelectionSpecCollection.Name)]
public class when_selecting_the_only_tenant_on_a_double_slash_path(TenantSelectionHarness harness) : Specification
{
    HttpStatusCode _status;
    string? _location;

    void Establish() => harness.UserBelongsTo(TenantSelectionHarness.TenantA);

    async Task Because()
    {
        using var client = harness.CreateSecurityClient();
        using var request = TenantSelectionHarness.Request("http://localhost//other.example/", SecurityHarness.UniqueUser("single-tenant-path"));
        using var response = await client.SendAsync(request);
        _status = response.StatusCode;
        _location = response.Headers.Location?.OriginalString;
    }

    [Fact] void should_redirect() => _status.ShouldEqual(HttpStatusCode.Redirect);
    [Fact] void should_redirect_to_the_application_root() => _location.ShouldEqual("/");
}
