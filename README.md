Authentication Server Sample
======

Spec
-----
* JDK 1.8
* Maven 3.6.1
* Spring boot
* Spring SAML2
* Spring oAuth2

Setup
------
* Project 폴더를 생성합니다.
* Intellij 를 실행하여 Project를 Open 합니다.
* Intellij에서 프로젝트 소스에서 오류가 날 경우 Lombok Plug-in을 다음의 링크를 참조하여 설치해야 합니다.<br/>

``` 
Lombok 사용 시 IntelliJ Setting - http://blog.egstep.com/java/2018/01/12/intellij-lombok/ 
```

* 되도록이면 Project-Structure 에서 프로젝트의 JDK 버전을 1.8로 맞춥니다.
* 수동 빌드할 경우 Maven 3 이상의 버전으로 실행합니다. 
```bash
 ~bizflowsaml % nvm install
```
* 수동 실행의 경우 다음과 같이 실행합니다.
```bash
 ~bizflowsaml/bizflowsaml-idp/target % java -jar bizflowsaml-idp-0.0.1.jar
 ~bizflowsaml/bizflowsaml-sp/target % java -jar bizflowsaml-sp-0.0.1.jar
```

* Thymleaf live reload 설정 : application.yaml 에 local 설정에 보면 다음 과 같은 옵션으로 devtools과 thymleaf 설정을 합니다.
```
spring:
  devtools:
    livereload:
      enabled: true
  thymeleaf:
    cache: false
``` 
자세한 설정 방법은 "https://elfinlas.github.io/2017/12/25/springbootstaticres/" 문서를 참고하세요.
