package com.coherent.unnamed.auth.util;

import com.coherent.unnamed.auth.constant.Constants;
import com.coherent.unnamed.auth.dto.AuthRefreshTokenDTO;
import com.coherent.unnamed.auth.dto.AuthRequestBean;
import com.coherent.unnamed.auth.exception.AuthServiceException;
import com.coherent.unnamed.auth.exception.ErrorCode;
import com.coherent.unnamed.auth.model.enity.OauthTokenDetail;
import com.coherent.unnamed.auth.model.enity.User;
import com.coherent.unnamed.auth.repository.OauthTokenDetailRepository;
import com.coherent.unnamed.auth.repository.UserRepository;
import com.coherent.unnamed.auth.response.AuthBaseResponse;
import com.coherent.unnamed.auth.response.AuthResponse;
import com.coherent.unnamed.auth.service.impl.UserDetailServiceImpl;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.*;
import java.util.regex.Matcher;


@Component
public class AuthUtills {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserDetailServiceImpl.class);



    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OauthUtills authUtills;

    @Autowired
    private OauthTokenDetailRepository oauthTokenDetRepository;

    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void setAuthUtills(OauthUtills authUtills) {
        this.authUtills = authUtills;
    }

    public void setOauthTokenDetRepository(OauthTokenDetailRepository oauthTokenDetRepository) {
        this.oauthTokenDetRepository = oauthTokenDetRepository;
    }

    public static boolean validate(String emailStr) {
        Matcher matcher = Constants.VALID_EMAIL_ADDRESS_REGEX.matcher(emailStr);
        if(matcher.find()){
            return emailStr.endsWith(Constants.COHERENT);
        }
        return false;
    }

    public AuthBaseResponse authenticate(AuthRequestBean requestBean) {

        Map<String, Object> responseMap = new HashMap<String, Object>();

        AuthResponse authResponse = new AuthResponse();
        AuthBaseResponse baseResponse = new AuthBaseResponse();
        LOGGER.info("Welcome to authenticate() in AuthUtils :::");

       // JSONObject jsonRes = new JSONObject();

        if (Objects.nonNull(requestBean)) {
            String email = requestBean.getEmail();
            if (!validate(email)) {
                LOGGER.error("Username should be coherent id");
                throw new AuthServiceException(HttpStatus.UNAUTHORIZED.value(), Constants.USERNAME_SHOULD_BE_COHERENT_ID);
            }
           Optional<User>  user = null;
            try {
                user = userRepository.findByEmail(email);
                if (user == null) {
                    throw new AuthServiceException(HttpStatus.UNAUTHORIZED.value(), Constants.USER_NOT_FOUND);
                }
                boolean value = validateRequestParams(requestBean,user.get());

                if(value){
                    authResponse = authUtills.jwtTokenGenerator(user.get(), responseMap, userRepository, oauthTokenDetRepository, true);

                    baseResponse.setAuthResponse(authResponse);
                } else{
                    throw new AuthServiceException(HttpStatus.UNAUTHORIZED.value(),Constants.ERROR_INVALID_OTP);
                }
            } catch (Exception e) {
                throw new AuthServiceException(HttpStatus.UNAUTHORIZED.value(), Constants.ERROR_INCORRECT_OTP);
            }
        } else {
            LOGGER.error("In-sufficient input request");
            throw new AuthServiceException(HttpStatus.UNAUTHORIZED.value(), Constants.MANDATORY_INPUT_MISSING);
        }
        return baseResponse;
    }




 /*   private boolean validateEmailAndOtp(String email,Integer otp,User user){
        boolean value = false;
        if(email.equals(user.getEmail())){
            return value= true;
        }
            return value;
    }*/

    private boolean validateRequestParams(AuthRequestBean requestBean,User user) {
     /*   int userOtp=user.getOtp();
        int reqOtp= requestBean.getOtp();*/
        if (user.getOtp().equals(requestBean.getOtp())) {
            return !StringUtils.isEmpty(requestBean.getEmail()) && requestBean.getOtp() != null;
        } else {
            return false;
        }
    }

    public AuthResponse refreshToken(AuthRefreshTokenDTO authRefreshTokenDto) {
        Map<String, Object> responseMap = new HashMap<String, Object>();

        AuthResponse authResponse = null;

        if (authRefreshTokenDto != null && authRefreshTokenDto.getEmail() != null) {

            User user = userRepository.findByEmailAndIsActive(authRefreshTokenDto.getEmail(), Constants.ONE);

            if (user == null)
                throw new AuthServiceException(HttpStatus.INTERNAL_SERVER_ERROR.value(), ErrorCode.CAP_1002.getMessage());

            if (user.isEnabled()) {
                throw new AuthServiceException(HttpStatus.INTERNAL_SERVER_ERROR.value(), Constants.ERROR_ACCOUNT_DISABLED);
            }

            if (user.getIsActive() == 0) {
                throw new AuthServiceException(HttpStatus.INTERNAL_SERVER_ERROR.value(), Constants.ERROR_ACCOUNT_LOCKED);
            }
            List<OauthTokenDetail> extTokenDetList = oauthTokenDetRepository.getTokenDetailByUserId(user.getId());

            boolean vFlag = false;

            if (extTokenDetList != null && extTokenDetList.size() > 0) {

                LOGGER.debug("----vFlag---in extTokenDetList.size()--" + extTokenDetList.size());

                for (OauthTokenDetail tokenDet : extTokenDetList) {

                    if (tokenDet != null && tokenDet.getRefreshToken().equalsIgnoreCase(authRefreshTokenDto.getRefreshToken())) {
                        vFlag = true;
                        break;
                    }
                }
            }

            LOGGER.debug("----vFlag---in refreshToken--" + vFlag);

            try {

                if (vFlag) {

                    authResponse = authUtills.jwtTokenGenerator(user, responseMap, userRepository, oauthTokenDetRepository, false);

                } else {
                    throw new AuthServiceException(HttpStatus.UNAUTHORIZED.value(), ErrorCode.CAP_1018.getMessage());

                }
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                throw new AuthServiceException(HttpStatus.INTERNAL_SERVER_ERROR.value(), e.getMessage());
            }

            return authResponse;

        } else {

            throw new AuthServiceException(HttpStatus.NOT_FOUND.value(), ErrorCode.CAP_1002.getMessage());
        }
    }
}