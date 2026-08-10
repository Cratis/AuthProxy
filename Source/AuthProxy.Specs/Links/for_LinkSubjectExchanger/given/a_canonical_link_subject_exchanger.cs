// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Links.for_LinkSubjectExchanger.given;

public class a_canonical_link_subject_exchanger : a_link_subject_exchanger
{
    protected override LinkSubjectExchanger CreateExchanger(
        C.AuthProxy configuration,
        IOptionsMonitor<C.AuthProxy> optionsMonitor,
        IHttpClientFactory httpClientFactory)
    {
        var authenticationOptions = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authenticationOptions.CurrentValue.Returns(configuration.Authentication);
        return new(
            optionsMonitor,
            httpClientFactory,
            Substitute.For<ILogger<LinkSubjectExchanger>>(),
            new CanonicalIdentityResolver(authenticationOptions));
    }
}
