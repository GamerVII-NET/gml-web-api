using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Gml.WebApi.Middlewares;

public class BasicAuthMiddleware : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public BasicAuthMiddleware(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger,
        UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }

    public BasicAuthMiddleware(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger,
        UrlEncoder encoder) : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authHeader = Request.Headers.Authorization.ToString();

        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Basic", StringComparison.OrdinalIgnoreCase))
        {
            var token = authHeader.Substring("Basic".Length).Trim();

            Console.WriteLine($"Auth by token: {token}");

            var credentionalsString = Encoding.UTF8.GetString(Convert.FromBase64String(token));
            var credentionals = credentionalsString.Split(':');

            if (CheckLogin(credentionals))
            {
                var claims = new List<Claim>
                {
                    new("Name", credentionals[0]),
                    new("Role", "Admin")
                };

                var identityClaims = new ClaimsIdentity(claims, "Basic");
                var claimPrincipal = new ClaimsPrincipal(identityClaims);

                Console.WriteLine($"Success auth");

                return Task.FromResult(
                    AuthenticateResult.Success(new AuthenticationTicket(claimPrincipal, Scheme.Name)));
            }
        }

        Console.WriteLine($"Error auth");

        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.FromResult(AuthenticateResult.Fail("Invalid authorization header"));
    }

    private static bool CheckLogin(string[] credentionals)
    {
        return credentionals is ["admin", "admin"];
    }
}
