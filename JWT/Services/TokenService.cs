using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWT.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JWT.Services;

public interface ITokenService
{
    string? GetToken(string username);
}

public class TokenService : ITokenService
{
    private readonly IUserService _userService;
    private readonly IOptions<JwtOptions> _jwtOptions;

    public TokenService(IUserService userService, IOptions<JwtOptions> jwtOptions)
    {
        _userService = userService;
        _jwtOptions = jwtOptions;
    }

    public string? GetToken(string username)
    {
        var user = _userService.GetUser(username);

        if (user == null) return null;

        var token = GenerateToken(user);
        return token;
    }

    private string? GenerateToken(User user)
    {
        var now = DateTimeOffset.Now;
        var claims = new List<Claim>();

        // Registered Claim Names: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1

        claims.Add(new Claim(ClaimTypes.Name, user.Username));
        claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
        claims.AddRange(user.Roles.Select(role => new Claim(ClaimTypes.Role, role.ToString())));

        // The "iat" (issued at) claim identifies the time at which the JWT was issued.  
        // This claim can be used to determine the age of the JWT.  Its value MUST be a number containing a NumericDate value.  Use of this claim is OPTIONAL.
        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
        claims.Add(new Claim(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString()));

        // The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.  
        // The processing of the "nbf" claim requires that the current date/time MUST be after or equal to the not-before date/time listed in the "nbf" claim.  
        // Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.  
        // Its value MUST be a number containing a NumericDate value.  Use of this claim is OPTIONAL.
        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
        claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, now.ToUnixTimeSeconds().ToString()));

        // The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.  
        // The processing of the "exp" claim requires that the current date/time MUST be before the expiration date/time listed in the "exp" claim. 
        // Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.  
        // Its value MUST be a number containing a NumericDate value.  Use of this claim is OPTIONAL.
        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
        claims.Add(new Claim(JwtRegisteredClaimNames.Exp, now.AddDays(1).ToUnixTimeSeconds().ToString()));

        // The "iss" (issuer) claim identifies the principal that issued the JWT.The processing of this claim is generally application specific.
        // The "iss" value is a case-sensitive string containing a StringOrURI value.Use of this claim is OPTIONAL.
        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
        claims.Add(new Claim(JwtRegisteredClaimNames.Iss, _jwtOptions.Value.Issuer));

        // The "aud" (audience) claim identifies the recipients that the JWT is intended for.
        // Each principal intended to process the JWT MUST identify itself with a value in the audience claim.
        // If the principal processing the claim does not identify itself with a value in the "aud" claim when this claim is present, then the JWT MUST be rejected. 
        // In the general case, the "aud" value is an array of case-sensitive strings, each containing a StringOrURI value.  
        // In the special case when the JWT has one audience, the "aud" value MAY be a single case-sensitive string containing a StringOrURI value.  
        // The interpretation of audience values is generally application specific. Use of this claim is OPTIONAL.
        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
        claims.Add(new Claim(JwtRegisteredClaimNames.Aud, _jwtOptions.Value.Audience));
        
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.Value.SecretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var header = new JwtHeader(credentials);
        var payload = new JwtPayload(claims);
        var securityToken = new JwtSecurityToken(header, payload);

        var token = new JwtSecurityTokenHandler().WriteToken(securityToken);
        return token;
    }
}