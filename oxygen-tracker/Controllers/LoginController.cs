using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using oxygen_tracker.Controllers.Services;
using oxygen_tracker.Models;
using oxygen_tracker.Services;
using System;
using System.Threading.Tasks;

namespace oxygen_tracker.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IJwtTokenService _jwtTokenService;
        public LoginController(IUserService userService,IJwtTokenService jwtTokenService)
        {
            this._userService = userService;
            this._jwtTokenService = jwtTokenService;
        }

        [HttpPost]
        public async Task<IActionResult> LoginUserAsync(RegisterModel model)
        {
            var result = await _userService.RegisterAsync(model);
            if(result.ErrorCodes == Constants.DefaultValues.ErrorCodes.None)SetRefreshTokenInCookie(result.RefreshToken);
            return Ok(result);
        }

        private void SetRefreshTokenInCookie(string refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(10),
            };
            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var response = await _jwtTokenService.RefreshTokenAsync(refreshToken);
            if (!string.IsNullOrEmpty(response.RefreshToken))
                SetRefreshTokenInCookie(response.RefreshToken);
            return Ok(response);
        }

        [HttpPost("revoke-token")]
        public IActionResult RevokeToken([FromBody] RevokeTokenRequest model)
        {
            // accept token from request body or cookie
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is required" });

            var response = _jwtTokenService.RevokeToken(token);

            if (!response)
                return NotFound(new { message = "Token not found" });

            return Ok(new { message = "Token revoked" });
        }

    }
}