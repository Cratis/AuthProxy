// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using E2E.OAuthGrantClient;

using var lane = new GrantLane();
try
{
    await lane.Run();
    return 0;
}
catch (Exception error)
{
    // Do not dump tokens, response bodies or arbitrary exception diagnostics on failure.
    Console.WriteLine(error is InvalidOperationException ? error.Message : "FAIL: unexpected OAuth-grant driver failure");
    return 1;
}
