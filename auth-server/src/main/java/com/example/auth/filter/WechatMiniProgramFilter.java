package com.example.auth.filter;

import com.example.auth.token.WechatMiniProgramAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;


public class WechatMiniProgramFilter extends AbstractAuthenticationProcessingFilter {

    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/loginByWechatMiniProgram", "POST");

    public WechatMiniProgramFilter() {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }

//    private WechatUserService wechatUserService;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        } else {
            String code = request.getParameter("js_code");
            if (!StringUtils.hasText(code)) {
                throw new BadCredentialsException("无效CODE");
            }
//            WechatMiniProgramLoginResult result = wechatUserService.loginWechatMiniProgram(code);
//            if (result == null) {
//                throw new BadCredentialsException("微信登录失败");
//            }
//            if(!StringUtils.hasText(result.getOpenid())) {
//                throw new BadCredentialsException("微信OPENID错误");
//            }
            WechatMiniProgramAuthenticationToken token = new WechatMiniProgramAuthenticationToken("result.getOpenid()");
            token.setDetails(this.authenticationDetailsSource.buildDetails(request));
            return this.getAuthenticationManager().authenticate(token);
        }
    }

//    public WechatUserService getWechatUserService() {
//        return wechatUserService;
//    }
//
//    public void setWechatUserService(WechatUserService wechatUserService) {
//        this.wechatUserService = wechatUserService;
//    }
}
