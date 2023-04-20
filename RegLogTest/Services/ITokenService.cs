using RegLogTest.Models;
using System.IdentityModel.Tokens.Jwt;

namespace RegLogTest.Services
{
    public interface ITokenService
    {
        JwtSecurityToken Generate(string username);
    }
}
