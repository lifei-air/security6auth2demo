介绍

Spring Security OAuth2 默认实现的四种授权模式在实际的应用场景中往往满足不了预期。 需要扩展如下需求：

● 手机号+短信验证码登陆

● 微信授权登录

本次主要通过继承Spring Security OAuth2 抽象类和接口，来实现对oauth2/token接口的手机号+短信的认证授权。

代码
https://gitee.com/LearningTech/springoatuh2

开发环境

● JDK 17

● Spring Boot 3

核心概念和流程

● SecurityFilterChain: 表示Spring Security的过滤器链。实现安全配置和认证扩展配置

● RegisteredClientRepository： 表示自定义的授权客户端信息，需要进行配置。这个客户端信息是oauth2/token中需要进行认证的信息。

● AbstractAuthenticationToken: 表示用户认证信息。 需要对其进行扩展

●  AuthenticationProvider： 验证登录信息，实现token的生成。需要对其进行扩展

● AuthenticationConverter： 实现对AbstractAuthenticationToken自定义扩展类的转换。

主要流程就是，实现上述AbstractAuthenticationToken、AuthenticationProvider、AuthenticationConverter三个抽象类和接口的扩展。并通过实现AuthenticationSuccessHandler扩展类，用来返回token给http response中。