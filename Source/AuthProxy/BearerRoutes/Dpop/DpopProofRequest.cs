// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>The trusted request and access-token context against which one proof must verify.</summary>
/// <param name="Method">The exact HTTP method.</param>
/// <param name="Target">The trusted public escaped target.</param>
/// <param name="Token">The exact access-token bytes as ASCII.</param>
/// <param name="Jkt">The signed token's canonical confirmation thumbprint.</param>
/// <param name="Now">The Redis-checked current Unix time.</param>
internal sealed record DpopProofRequest(string Method, string Target, string Token, string Jkt, long Now);
