using JWTAPI.Models;
using JWTAPI.Models.Custom;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTAPI.Service
{
    public class AuthorizationService : IAuthorizationService
    {
        private readonly JwtBasicsCeContext _context;
        private readonly IConfiguration _configuration;
        public AuthorizationService(JwtBasicsCeContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        private string GenerarToken(string idUsuario)
        {
            var key = _configuration.GetValue<string>("JwtSettings:Key");
            var keyBytes = Encoding.ASCII.GetBytes(key);

            var claims = new ClaimsIdentity();
            claims.AddClaim(new Claim(ClaimTypes.NameIdentifier, idUsuario));

            var credentialsToken = new SigningCredentials(
                new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256Signature);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claims,
                Expires = DateTime.UtcNow.AddMinutes(2),
                SigningCredentials = credentialsToken
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenConfig = tokenHandler.CreateToken(tokenDescriptor);

            string tokenCreado = tokenHandler.WriteToken(tokenConfig);

            return tokenCreado;
        }

        public async Task<AuthorizationResponse> DevolverToken(AuthorizationRequest authorization)
        {
            var usuario_encontrado = _context.Usuarios.FirstOrDefault(x => x.NombreUsuario == authorization.NombreUsuario && x.Clave == authorization.clave);

            if(usuario_encontrado == null)
            {
                return await Task.FromResult<AuthorizationResponse>(null);
            }

            string tokenCreado = GenerarToken(usuario_encontrado.IdUsuario.ToString());

            string refreshTokenCreado = GenerarRefreshToken();

            //return new AuthorizationResponse() { Token = tokenCreado, Resultado = true, Message = "Ok" };

            return await GuardarHistorialRefreshToken(usuario_encontrado.IdUsuario, tokenCreado, refreshTokenCreado);


        }


        private string GenerarRefreshToken()
        {
            var byteArray = new byte[64];
            var refreshToken = "";

            using (var mg = RandomNumberGenerator.Create())
            {
                mg.GetBytes(byteArray);
                refreshToken = Convert.ToBase64String(byteArray);
            }
            return refreshToken;
        }

        private async Task<AuthorizationResponse> GuardarHistorialRefreshToken(int idUsuario,string token, string refreshToken)
        {
            var historialRefreshToken = new HistorialRefreshToken { IdUsuario = idUsuario, Token = token, 
                RefreshToken = refreshToken,
                FechaCreacion = DateTime.UtcNow,
                FechaExpiracion = DateTime.UtcNow.AddMinutes(2) };


            await _context.HistorialRefreshTokens.AddAsync(historialRefreshToken);
            await _context.SaveChangesAsync();

            return new AuthorizationResponse() { Token = token, RefreshToken = refreshToken, Resultado = true, Message = "ok" };
        }

        public async Task<AuthorizationResponse> DevolverRefreshToken(RefreshTokenRequest refreshTokenRequest, int idUsuario)
        {
            var refreshTokenEncontrado = _context.HistorialRefreshTokens.FirstOrDefault(x => x.Token == refreshTokenRequest.TokenExpirado &&
            x.RefreshToken == refreshTokenRequest.RefreshToken && x.IdUsuario == idUsuario);

            if(refreshTokenEncontrado == null || refreshTokenEncontrado.EsActivo == false)
            {
                return new AuthorizationResponse { Resultado = false, Message = "No existe refreshToken" };
            }

            var refreshTokenCreado = GenerarRefreshToken();
            var tokenCreado = GenerarToken(idUsuario.ToString());


            return await GuardarHistorialRefreshToken(idUsuario, tokenCreado, refreshTokenCreado);
        }
    }
}
