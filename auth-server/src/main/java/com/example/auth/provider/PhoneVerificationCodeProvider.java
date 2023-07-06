package com.example.auth.provider;

import com.example.auth.token.PhoneVerificationCodeAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class PhoneVerificationCodeProvider implements AuthenticationProvider {

//    private AuthUserLoginService authUserLoginService;
//
//    private AuthUserSupportService authUserSupportService;
//
//    private final PreAuthenticationChecks preAuthenticationChecks = new PreAuthenticationChecks();
//    private final PostAuthenticationChecks postAuthenticationChecks = new PostAuthenticationChecks();

    private static final Logger logger = LoggerFactory.getLogger(PhoneVerificationCodeProvider.class);

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
//            UserLoginDto userLoginDto = new UserLoginDto();
//            userLoginDto.setPhone(authentication.getPrincipal().toString());
//            userLoginDto.setCode(authentication.getCredentials().toString());
//            Boolean isCodePass = authUserSupportService.verifyPhoneCode(userLoginDto);
//            if (!isCodePass) {
//                throw new BadCredentialsException("验证码错误");
//            }
//            UserDetails loadedUser = authUserLoginService.loadUserByPhoneNumber(authentication.getPrincipal().toString());
//            if (loadedUser == null) {
//                throw new ServiceException("手机登录失败");
//            }
//            this.preAuthenticationChecks.check(loadedUser);
//            PhoneVerificationCodeAuthenticationToken result = new PhoneVerificationCodeAuthenticationToken(loadedUser, authentication.getCredentials(), loadedUser.getAuthorities());
//            this.postAuthenticationChecks.check(loadedUser);
//            logger.debug("Authenticated user");
            return null;
        } catch (Exception var4) {
            logger.info(var4.getMessage());
            throw new BadCredentialsException(var4.getMessage());
        }
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return PhoneVerificationCodeAuthenticationToken.class.isAssignableFrom(aClass);
    }

}
