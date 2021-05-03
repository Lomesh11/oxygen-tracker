using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using oxygen_tracker.Controllers.Services;
using oxygen_tracker.Models;
using oxygen_tracker.Services;
using System.Threading.Tasks;

namespace oxygen_tracker.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IJwtTokenService _jwtTokenService;

        public UserController(IUserService userService,IJwtTokenService jwtTokenService)
        {
            _userService = userService;
            _jwtTokenService = jwtTokenService;
        }

        [HttpGet("{phone}")]
        public async Task<ActionResult<UserDetail>> GetUser(string phone)
        {
            var userDetail = await _userService.GetUserInfoAsync(phone);
            return Ok(userDetail);
        }
    }
}