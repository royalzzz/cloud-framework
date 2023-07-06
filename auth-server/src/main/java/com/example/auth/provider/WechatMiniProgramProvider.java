package com.example.auth.provider;

import com.example.auth.token.WechatMiniProgramAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class WechatMiniProgramProvider implements AuthenticationProvider {

//    private AuthUserLoginService authUserLoginService;
//
//    private AuthUserSupportService authUserSupportService;


    private static final Logger logger = LoggerFactory.getLogger(WechatMiniProgramProvider.class);

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        UserDetails loadedUser = authUserLoginService.loadUserByWechatMiniProgram(authentication.getPrincipal().toString());
//        if (loadedUser == null) {
//            throw new ServiceException("微信登录失败");
//        }
//        this.preAuthenticationChecks.check(loadedUser);
//        WechatMiniProgramAuthenticationToken result = new WechatMiniProgramAuthenticationToken(loadedUser, authentication.getCredentials(), null);
//        this.postAuthenticationChecks.check(loadedUser);
//        logger.debug("Authenticated user");
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return WechatMiniProgramAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
