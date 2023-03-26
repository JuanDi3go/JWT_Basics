using JWTAPI.Models.Custom;
using JWTAPI.Service;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using System.IdentityModel.Tokens.Jwt;

namespace JWTAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsuarioController : ControllerBase
    {
        private readonly IAuthorizationService _authorizationService;

        public UsuarioController(IAuthorizationService authorizationService)
        {
            _authorizationService = authorizationService;
        }

        [HttpPost]
        [Route("Autenticar")]
        public async Task<IActionResult> Autenticar([FromBody] AuthorizationRequest autorizacion)
        {
            var resultado_autorizacion = await _authorizationService.DevolverToken(autorizacion);
            if (resultado_autorizacion == null)
            {
                return Unauthorized();
            }

            return Ok(resultado_autorizacion);
        }


        [HttpPost]
        [Route("ObtenerRefreshToken")]
        public async Task<IActionResult> Autenticar([FromBody] RefreshTokenRequest request)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenExpiradoSupuestamente = tokenHandler.ReadJwtToken(request.TokenExpirado);

            if(tokenExpiradoSupuestamente.ValidTo > DateTime.UtcNow)
            {
                return BadRequest(new AuthorizationResponse { Resultado = false, Message = "Token no ha expirado" });
            }

            string idUsuario = tokenExpiradoSupuestamente.Claims.First(x => x.Type == System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.NameId).Value.ToString();

            var autorizacionResponse = await _authorizationService.DevolverRefreshToken(request, int.Parse(idUsuario));

            if (autorizacionResponse.Resultado == true)
                return Ok(autorizacionResponse);
            else
                return BadRequest(autorizacionResponse);
        }
    }
}
