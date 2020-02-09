package com.zhy.controller;

import com.zhy.constant.CodeType;
import com.zhy.model.User;
import com.zhy.redis.StringRedisServiceImpl;
import com.zhy.service.UserService;
import com.zhy.utils.JsonResult;
import com.zhy.utils.MD5Util;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;
import java.security.Principal;

/**
 * @author: zhangocean
 * @Date: 2018/6/8 9:24
 * Describe: 登录控制
 */
@RestController
public class LoginControl {

    @Autowired
    UserService userService;
    @Autowired
    StringRedisServiceImpl stringRedisService;

    @RequestMapping("changePassword")
    public String changePassword(
                                 @RequestParam("oldPassword") String oldPassword,
                                 @RequestParam("newPassword") String newPassword,
                                 @AuthenticationPrincipal Principal principal){

       // String trueMsgCode = (String) stringRedisService.get(phone);

        //判断获得的手机号是否是发送验证码的手机号
//        if(trueMsgCode == null){
//            return JsonResult.fail(CodeType.PHONE_ERROR).toJSON();
//        }
//        //判断验证码是否正确
//        if(!authCode.equals(trueMsgCode)){
//            return JsonResult.fail(CodeType.AUTH_CODE_ERROR).toJSON();
//        }
        String username = principal.getName();
        User user = userService.findUserByUsername(username);
        if(user == null){
            return JsonResult.fail(CodeType.USERNAME_NOT_EXIST).toJSON();
        }

        MD5Util md5Util = new MD5Util();
        String mD5Password = md5Util.encode(oldPassword);
        if (!user.getPassword().equals(mD5Password)){
            return JsonResult.fail(CodeType.PASSWORD_ERROR).toJSON();
        }
         mD5Password = md5Util.encode(newPassword);
        if (user.getPassword().equals(mD5Password)){
            return JsonResult.fail(CodeType.PASSWORD_EQ).toJSON();
        }
        userService.updatePasswordByPhone(user.getPhone(),mD5Password);

        //修改密码成功删除redis中的验证码
        //stringRedisService.remove(phone);

        return JsonResult.success().toJSON();
    }

}
