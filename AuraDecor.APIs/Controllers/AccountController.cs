using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using AuraDecor.APIs.Dtos.Incoming;
using AuraDecor.APIs.Dtos.Outgoing;
using AuraDecor.APIs.Errors;
using AuraDecor.APIs.Extensions;
using AuraDecor.APIs.Helpers;
using AuraDecor.Core.Entities;
using AuraDecor.Core.Services.Contract;
using AutoMapper;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.Twitter;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuraDecor.APIs.Controllers;
public class AccountController : ApiBaseController
{
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IMapper _mapper;
        private readonly IEmailService _emailService;
        private readonly ITokenService _authService;

        public AccountController(UserManager<User> userManager, SignInManager<User> signInManager, IMapper mapper,
          IEmailService emailService ,ITokenService authService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _mapper = mapper;
            _emailService = emailService;
            _authService = authService;
        }
        [RateLimit(2, 10, RateLimitAlgorithm.SlidingWindow)]  

        [HttpPost("login")]
        public async Task<ActionResult<AuthResponseDto>> Login(LoginDto loginDto)
        {
            var user = await _userManager.FindByEmailAsync(loginDto.Email);
            if (user == null)
            {
                return Unauthorized(new ApiResponse(401));
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, loginDto.Password, false);
            
            if (!result.Succeeded)
            {
                return Unauthorized(new ApiResponse(401));
            }

            if (user.TwoFactorEnabled)
            {
                return StatusCode(StatusCodes.Status202Accepted, new { IsTwoFactorRequired = true, Message = "Two-factor authentication required" });
            }

            var token = await _authService.CreateTokenAsync(user, _userManager);
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(token);
            var jwtId = jwtToken.Id;
            
            var refreshToken = await _authService.GenerateRefreshTokenAsync(user.Id, jwtId);
            
            await _authService.StoreRefreshTokenAsync(refreshToken);
            
            return new AuthResponseDto
            {
                DisplayName = user.DisplayName,
                Email = user.Email,
                Phone = user.PhoneNumber,
                Token = token,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiry = refreshToken.Expires
            };
        }
        [RateLimit(2, 10, RateLimitAlgorithm.SlidingWindow)]  

        [HttpPost("register")]
        public async Task<ActionResult<AuthResponseDto>> Register(RegisterDto registerDto)
        {
            if (CheckEmailExistsAsync(registerDto.Email).Result.Value)
            {
                return BadRequest(new ApiValidationErrorResponse() { Errors = new[] { "Email address is in use" } });
            }
            if (await _userManager.FindByNameAsync(registerDto.UserName) != null)
            {
                return BadRequest(new ApiValidationErrorResponse() { Errors = new[] { "Username is in use" } });
            }

            var user = new User
            {
                DisplayName = registerDto.DisplayName,
                Email = registerDto.Email,
                UserName = registerDto.UserName,
                PhoneNumber = registerDto.PhoneNumber
            };
            
            var result = await _userManager.CreateAsync(user, registerDto.Password);
            if (!result.Succeeded)
            {
                return BadRequest(new ApiResponse(400));
            }

            var token = await _authService.CreateTokenAsync(user, _userManager);
            
            var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(token);
            var jwtId = jwtToken.Id;
            
            var refreshToken = await _authService.GenerateRefreshTokenAsync(user.Id, jwtId);
            
            await _authService.StoreRefreshTokenAsync(refreshToken);
            
            return new AuthResponseDto
            {
                DisplayName = user.DisplayName,
                Email = user.Email,
                Phone = user.PhoneNumber,
                Token = token,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiry = refreshToken.Expires
            };
        }
        
        [HttpPost("refresh")]
        public async Task<ActionResult<AuthResponseDto>> RefreshToken(RefreshTokenDto refreshTokenDto)
        {
            if (refreshTokenDto == null || string.IsNullOrEmpty(refreshTokenDto.AccessToken) || 
                string.IsNullOrEmpty(refreshTokenDto.RefreshToken))
            {
                return BadRequest(new ApiResponse(400, "Invalid token information"));
            }
            
            try
            {
                var (accessToken, refreshToken) = await _authService.RefreshTokenAsync(
                    refreshTokenDto.AccessToken,
                    refreshTokenDto.RefreshToken,
                    _userManager);
                
                var userId = refreshToken.UserId;
                var user = await _userManager.FindByIdAsync(userId);
                
                return new AuthResponseDto
                {
                    DisplayName = user.DisplayName,
                    Email = user.Email,
                    Phone = user.PhoneNumber,
                    Token = accessToken,
                    RefreshToken = refreshToken.Token,
                    RefreshTokenExpiry = refreshToken.Expires
                };
            }
            catch (SecurityTokenException ex)
            {
                return Unauthorized(new ApiResponse(401, ex.Message));
            }
            catch (Exception ex)
            {
                return BadRequest(new ApiResponse(400, ex.Message));
            }
        }
        
        [Authorize]
        [HttpPost("revoke")]
        public async Task<ActionResult> RevokeToken(RefreshTokenDto refreshTokenDto)
        {
            var userId = User.FindFirstValue(JwtRegisteredClaimNames.NameId);
            
            if (string.IsNullOrEmpty(refreshTokenDto.RefreshToken))
            {
                return BadRequest(new ApiResponse(400, "Token is required"));
            }
            
            var result = await _authService.RevokeTokenAsync(userId, refreshTokenDto.RefreshToken);
            
            if (!result)
            {
                return BadRequest(new ApiResponse(400, "Failed to revoke token"));
            }
            
            return Ok(new ApiResponse(200, "Token revoked"));
        }
        
        [RateLimit(2, 10, RateLimitAlgorithm.SlidingWindow)]  
        [HttpGet("google-login")]
        public IActionResult GoogleLogin()
        {
            var properties = new AuthenticationProperties 
            { 
                RedirectUri = Url.Action("GoogleResponse") 
            };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("google-response")]
        public async Task<IActionResult> GoogleResponse()
        {
            var result = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);
    
            if (!result.Succeeded)
                return Unauthorized(new ApiResponse(401));

            var googleUser = result.Principal;
            var email = googleUser.FindFirst(ClaimTypes.Email)?.Value;
            var name = googleUser.FindFirst(ClaimTypes.Name)?.Value;

            var user = await _userManager.FindByEmailAsync(email);
    
            if (user == null)
            {
                user = new User
                {
                    Email = email,
                    UserName = email,
                    DisplayName = name,
                    EmailConfirmed = true 
                };

                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                    return BadRequest(new ApiResponse(400, "Failed to create user"));
            }

            var token = await _authService.CreateTokenAsync(user, _userManager);
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(token);
            var jwtId = jwtToken.Id;
            
            var refreshToken = await _authService.GenerateRefreshTokenAsync(user.Id, jwtId);
            
            await _authService.StoreRefreshTokenAsync(refreshToken);

            return Ok(new AuthResponseDto
            {
                DisplayName = user.DisplayName,
                Email = user.Email,
                Phone = user.PhoneNumber,
                Token = token,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiry = refreshToken.Expires
            });
        }

        [HttpGet("twitter-login")]
        public IActionResult TwitterLogin()
        {
            var properties = new AuthenticationProperties 
            { 
                RedirectUri = Url.Action("TwitterResponse") 
            };
            return Challenge(properties, TwitterDefaults.AuthenticationScheme);
        }

        [HttpGet("twitter-response")]
        public async Task<IActionResult> TwitterResponse()
        {
            var result = await HttpContext.AuthenticateAsync(TwitterDefaults.AuthenticationScheme);
    
            if (!result.Succeeded)
                return Unauthorized(new ApiResponse(401));

            var twitterUser = result.Principal;
            var nameIdentifier = twitterUser.FindFirst(ClaimTypes.NameIdentifier)?.Value; 
            var name = twitterUser.FindFirst(ClaimTypes.Name)?.Value;
            var screenName = twitterUser.FindFirst("urn:twitter:screenname")?.Value;
            
            var username = $"twitter_{nameIdentifier}";
            var email = $"{screenName}@twitter.com"; 
            
            var user = await _userManager.FindByNameAsync(username);
    
            if (user == null)
            {
                user = new User
                {
                    Email = email,
                    UserName = username,
                    DisplayName = name,
                    EmailConfirmed = true 
                };

                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                    return BadRequest(new ApiResponse(400, "Failed to create user"));
            }

            var token = await _authService.CreateTokenAsync(user, _userManager);
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(token);
            var jwtId = jwtToken.Id;
            
            var refreshToken = await _authService.GenerateRefreshTokenAsync(user.Id, jwtId);
            
            await _authService.StoreRefreshTokenAsync(refreshToken);

            return Ok(new AuthResponseDto
            {
                Email = user.Email,
                Token = token,
                DisplayName = user.DisplayName,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiry = refreshToken.Expires
            });
        }
        
        [Authorize]
        [HttpGet("address")]
        public async Task<ActionResult<Dtos.Outgoing.AddressDto>> GetUserAddress()
        {
            var email = User.FindFirstValue(ClaimTypes.Email);
            var user = await _userManager.FindUserWithAddressAsync(User);
            var address = _mapper.Map<Address, Dtos.Outgoing.AddressDto>(user.Address);
            if (address == null)
            {
                return NotFound(new ApiResponse(404));
                
            }
            return Ok(address);
        }

        [Authorize]
        [HttpPut("address")]
        public async Task<ActionResult<Dtos.Outgoing.AddressDto>> UpdateUserAddress(Dtos.Incoming.CreateAddressDto addressDto)
        {
            var user = await _userManager.FindUserWithAddressAsync(User);
            user.Address = _mapper.Map<Dtos.Incoming.CreateAddressDto, Address>(addressDto);
            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded) return Ok(_mapper.Map<Address, Dtos.Outgoing.AddressDto>(user.Address));
            return BadRequest("Problem updating the user");
        }
        [HttpGet]
        public async Task<ActionResult<AuthResponseDto>> GetCurrentUser()
        {
            var email = User.FindFirstValue(ClaimTypes.Email);

            var user = await _userManager.FindByEmailAsync(email);
            
            var token = await _authService.CreateTokenAsync(user, _userManager);
            
            var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(token);
            var jwtId = jwtToken.Id;
            
            var refreshToken = await _authService.GenerateRefreshTokenAsync(user.Id, jwtId);
            
            await _authService.StoreRefreshTokenAsync(refreshToken);

            return new AuthResponseDto
            {
                DisplayName = user.DisplayName,
                Email = user.Email,
                Phone = user.PhoneNumber,
                Token = token,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiry = refreshToken.Expires
            };
        }
        
        [ApiExplorerSettings(IgnoreApi = true)]
        [HttpGet("emailexists")]
        public async Task<ActionResult<bool>> CheckEmailExistsAsync([FromQuery] string email)
        {
            return await _userManager.FindByEmailAsync(email) != null;
        }
        
        [Authorize]
        [HttpPut("update")]
        public async Task<ActionResult<AuthResponseDto>> UpdateUser(UpdateUserDto updateUserDto)
        {
            var user = await _userManager.FindByEmailAsync(User.FindFirstValue(ClaimTypes.Email));
            if (user == null)
            {
                return NotFound(new ApiResponse(404, "User not found"));
            }

            user.DisplayName = updateUserDto.DisplayName;
            user.PhoneNumber = updateUserDto.PhoneNumber;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest(new ApiResponse(400, "Problem updating the user"));
            }

            return new AuthResponseDto
            {
                Email = user.Email,
                Token = await _authService.CreateTokenAsync(user, _userManager),
                DisplayName = user.DisplayName
            };
        }

        [Authorize]
        [HttpPut("updatepassword")]
        public async Task<ActionResult> UpdateUserPassword([FromBody] Dictionary<string, string> passwords)
        {
            if (!passwords.ContainsKey("currentPassword") || !passwords.ContainsKey("newPassword"))
            {
                return BadRequest(new ApiResponse(400, "Current and new passwords are required"));
            }

            var user = await _userManager.FindByEmailAsync(User.FindFirstValue(ClaimTypes.Email));
            if (user == null)
            {
                return NotFound(new ApiResponse(404, "User not found"));
            }

            var result =
                await _userManager.ChangePasswordAsync(user, passwords["currentPassword"], passwords["newPassword"]);
            if (!result.Succeeded)
            {
                return BadRequest(new ApiResponse(400, "Problem updating the password"));
            }

            return Ok();
        }
        [HttpPost("forgot-password")]
        public async Task<ActionResult> ForgotPassword([FromBody] ForgotPasswordDto forgotPasswordDto)
        {
            var user = await _userManager.FindByEmailAsync(forgotPasswordDto.Email);
            if (user == null)
                return Ok();

            var otp = GenerateOtp.GenerateRandomOtp();
            await _emailService.SendOtpEmailAsync(forgotPasswordDto.Email, otp);
    
            return Ok();
        }

        [HttpPost("verify-otp")]
        public async Task<ActionResult<string>> VerifyOtp([FromBody] VerifyOtpDto verifyOtpDto)
        {
            var isValid = await _emailService.ValidateOtpAsync(verifyOtpDto.Email, verifyOtpDto.Otp);
            if (!isValid)
                return BadRequest(new ApiResponse(400, "Invalid or expired OTP"));

            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(
                await _userManager.FindByEmailAsync(verifyOtpDto.Email));
    
            return Ok(new { resetToken });
        }
        [HttpPost("reset-password")]
        public async Task<ActionResult> ResetPassword([FromBody] ResetPasswordDto resetPasswordDto)
        {
            var user = await _userManager.FindByEmailAsync(resetPasswordDto.Email);
            if (user == null)
                return BadRequest(new ApiResponse(400, "Invalid request"));

            var result = await _userManager.ResetPasswordAsync(
                user, 
                resetPasswordDto.Token, 
                resetPasswordDto.NewPassword);

            if (!result.Succeeded)
                return BadRequest(new ApiResponse(400, "Could not reset password"));

            return Ok();
        }

        [Authorize]
        [HttpGet("2fa/setup")]
        public async Task<ActionResult<TwoFactorEnabledResponseDto>> GetTwoFactorSetup()
        {
            var user = await _userManager.FindByEmailAsync(User.FindFirstValue(ClaimTypes.Email));
            if (user == null) return NotFound(new ApiResponse(404, "User not found"));

            var key = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(key))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                key = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            var email = user.Email;
            var appName = "AuraDecor";
            var uri = string.Format("otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6", appName, email, key);

            // Generate QR code as Base64
            using var qrGenerator = new QRCoder.QRCodeGenerator();
            using var qrCodeData = qrGenerator.CreateQrCode(uri, QRCoder.QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new QRCoder.PngByteQRCode(qrCodeData);
            var qrCodeBytes = qrCode.GetGraphic(20);
            var qrCodeBase64 = Convert.ToBase64String(qrCodeBytes);

            return new TwoFactorEnabledResponseDto
            {
                SharedKey = key,
                AuthenticatorUri = uri,
                QrCodeBase64 = $"data:image/png;base64,{qrCodeBase64}"
            };
        }

        [Authorize]
        [HttpPost("2fa/enable")]
        public async Task<ActionResult<AuthResponseDto>> EnableTwoFactor([FromBody] TwoFactorDto twoFactorDto)
        {
            var user = await _userManager.FindByEmailAsync(User.FindFirstValue(ClaimTypes.Email));
            if (user == null) return NotFound(new ApiResponse(404, "User not found"));

            var verificationCode = twoFactorDto.Code.Replace(" ", string.Empty).Replace("-", string.Empty);
            var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

            if (!is2faTokenValid)
            {
                return BadRequest(new ApiResponse(400, "Invalid verification code"));
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            
            return Ok(new ApiResponse(200, "Two-factor authentication enabled"));
        }

        [Authorize]
        [HttpPost("2fa/disable")]
        public async Task<ActionResult> DisableTwoFactor()
        {
            var user = await _userManager.FindByEmailAsync(User.FindFirstValue(ClaimTypes.Email));
            if (user == null) return NotFound(new ApiResponse(404, "User not found"));

            var result = await _userManager.SetTwoFactorEnabledAsync(user, false);
            if (!result.Succeeded)
            {
                return BadRequest(new ApiResponse(400, "Failed to disable 2FA"));
            }

            return Ok(new ApiResponse(200, "Two-factor authentication disabled"));
        }

        [HttpPost("login-2fa")]
        public async Task<ActionResult<AuthResponseDto>> LoginWithTwoFactor([FromBody] TwoFactorLoginDto loginDto)
        {
            var user = await _userManager.FindByEmailAsync(loginDto.Email);
            if (user == null) return Unauthorized(new ApiResponse(401));

            if (!user.TwoFactorEnabled)
            {
                 return BadRequest(new ApiResponse(400, "Two-factor authentication is not enabled for this user"));
            }

            // Verify password first
            var passwordCheck = await _signInManager.CheckPasswordSignInAsync(user, loginDto.Password, false);
            if (!passwordCheck.Succeeded)
            {
                return Unauthorized(new ApiResponse(401, "Invalid credentials"));
            }

            // Then verify 2FA code
            var verificationCode = loginDto.Code.Replace(" ", string.Empty).Replace("-", string.Empty);
            var isValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

            if (!isValid)
            {
                return Unauthorized(new ApiResponse(401, "Invalid 2FA code"));
            }

            var token = await _authService.CreateTokenAsync(user, _userManager);
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(token);
            var jwtId = jwtToken.Id;
            
            var refreshToken = await _authService.GenerateRefreshTokenAsync(user.Id, jwtId);
            
            await _authService.StoreRefreshTokenAsync(refreshToken);
            
            return new AuthResponseDto
            {
                DisplayName = user.DisplayName,
                Email = user.Email,
                Phone = user.PhoneNumber,
                Token = token,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiry = refreshToken.Expires
            };
        }
}
