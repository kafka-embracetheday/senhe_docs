#### 1. 密码策略测试[弱口令集]

##### 预置条件

1. A1 管理员帐号 

2. 用户可以登录成功

3. 启动禁止弱口令

##### 步骤描述

1. 使用A1登录系统

2. 在用户创建处勾选创建用户

3. 取消随机密码，创建用户

4. 在自定义弱口令集中加入ASdf

5. 使用testcase登录系统

6. 首次登录需修改密码 产生效果1

7. 点击确认按钮 产生效果2

8. 使用A1登录系统

9. 将禁止弱口令取消

10. 创建用户A2

11. 登录用户A2，并首次修改密码 产生效果3

12. 使用A1登录系统

13. 开启禁用弱口令

14. 再次使用A2登录 产生效果4

##### 预期结果

1. 效果1：
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-16-03-47-image.png)

2. 效果2：登录成功
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-16-04-20-image.png)

3. 效果3：登录成功，其中123456是弱口令
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-17-10-00-50-image.png)

4. 效果4：登录成功

#### 2. 密码策略测试[非法短语]

##### 预置条件

1. A1 管理员帐号

2. 用户可以登录成功

3. 启动禁止非法短语

##### 步骤描述

1. 使用A1登录系统

2. 在用户创建处勾选创建用户

3. 取消随机密码，创建用户A2  用户名密码：

4. 使用A2进行登录 产生效果1

5. 在自定义非法短语中加入ASdf 产生效果2

6. 使用A2登录系统 产生效果3

7. 使用A1修改A2的密码为 ASdf!@34

8. 使用A2登录系统 产生效果4

9. 使用A1登录系统

10. 取消禁用非法短语 

11. 创建用户A3 testcase

12. 使用A3首次登录设置密码 testcaseAA12!@ 产生效果5

13. 使用A1开启禁用非法短语

14. 再次使用A3登录系统 产生效果6

##### 预期结果

1. 效果1：登录成功

2. 效果2：
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-16-09-37-image.png)

3. 效果3：登陆成功

4. 效果4：登录成功

5. 效果5：登录成功

6. 效果6：登录成功

#### 3. 密码策略测试[历史密码重复]

##### 预置条件

1. A1 管理员帐号

2. 用户可以登录成功

3. 历史密码重复设置为3

##### 步骤描述

1. 使用A1登录系统

2. 在用户创建处勾选创建用户

3. 取消随机密码，创建用户A2 testcase:ASdf!@12

4. 使用A2登录系统，首次登录修改密码为ASdf!@34

5. 修改密码处将testcase密重置为Asdf!@34 产生效果1

6. 修改密码处将testcase密重置为Asdf!@12 产生效果2

7. 修改密码处将testcase密重置为ASdf!@1234 产生效果3

##### 预期结果

1. 效果1
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-16-41-56-image.png)

2. 效果2：
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-16-43-20-image.png)

3. 效果3:
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-16-44-47-image.png)

#### 4. 密码策略测试[密码强度]

##### 预置条件

1. A1 管理员帐号

2. 用户可以登录成功

3. 默认密码强度为较高强度

##### 步骤描述

1. 使用A1登录系统

2. 在用户创建处勾选创建用户

3. 取消随机密码，尝试创建用户A2，并将密码设置为ASdf12 产生效果1

4. 将默认密码强度修改为中等强度 产生效果2

5. 取消随机密码，尝试创建用户A2，并将密码设置为ASdf12 产生效果3

6. 取消随机密码，尝试创建用户A2，并将密码设置为ASdf12!@ 产生效果4

7. 使用A2首次登录系统进行重置密码ASdf12 产生效果5

8. 将默认密码强度修改为简单强度 产生效果6

9. 创建用户A3

10. 使用A3首次登录系统进行重置密码asd111 产生效果7

11. 将默认密码强度修改为人性化密码 产生效果8

12. 创建用户A4

13. 使用A4首次登录系统进行重置密码ASdfg12! 产生效果9

##### 预期结果

1. 效果1：
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-16-50-25-image.png)

2. 效果2：
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-16-53-00-image.png)

3. 效果3：
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-16-53-37-image.png)

4. 效果4：用户A2创建成功

5. 效果5：
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-16-57-07-image.png)

6. 效果6：
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-17-01-07-image.png)

7. 效果7：登录成功

8. 效果8：
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-17-03-33-image.png)

9. 效果9：成功
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-17-05-16-image.png)

#### 5. 密码策略测试[密码最长有效期]

##### 预置条件

1. A1 管理员帐号

2. 用户可以登录成功

3. 密码最长有效期设置为15天

##### 步骤描述

1. 等待15天

2. 登录系统

##### 预期结果

步骤2后将强制用户修改密码

#### 6. 认证方式测试[微信扫码登录]

##### 预置条件

1. 用户可以登录成功

2. 用户绑定微信扫码登录

3. 认证方式关闭微信扫码登录

##### 步骤描述

1. 访问登录页 产生效果1

2. 微信扫码授权登录 产生效果2

3. 开启微信扫码登录

4. 重复步骤1、2 产生效果3

5. 开启微信扫码登录的强制绑定

6. 创建用户A1

7. 使用A1首次登录系统 产生效果4

8. 关闭微信扫码登录的强制绑定

9. 创建用户A2

10. 使用A2首次登录系统，产生效果5

##### 预期结果

1. 效果1：主页登录方式 密码登录消失
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-17-10-40-44-image.png)

2. 效果2：跳到绑定页，而不是系统首页，点击确认并继续按钮无效果
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-17-10-30-26-image.png)

3. 效果3：登录成功

4. 效果4：
   
   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-17-10-57-29-image.png)

5. 效果5：直接登陆成功，无效果4

#### 7. 登录安全测试

##### 预置条件

1. 可登录的帐号A1

2. 账户锁定：连续失败次数为3 账户锁定时间为10分钟

3. IP锁定：连续失败次数为5 IP锁定时间为10分钟

##### 步骤描述

1. 使用错误密码登录系统 产生效果1

2. 重复步骤1三次 产生效果2

3. 等待10分钟

4. 使用正确密码登录系统 产生效果3

5. 手动跳转到登录页并重复步骤1五次 产生效果4

6. 等待10分钟

7. 使用正确密码登录系统 产生效果5

##### 预期结果

1. 效果1：

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-17-14-45-image.png)

2. 效果2：

  ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-15-17-13-52-image.png)

3. 效果3：登录成功

4. 效果4：

![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-17-15-58-image.png)

5. 效果5：登录成功

#### 8. 登录安全测试[账号锁定]

##### 预置条件

1. 关闭多因子认证

2. 用户已注册account

3. account未被锁定

4. 错误的用户名密码

5. 配置账户锁定连续失败次数为3次

##### 步骤描述

1. 在“用户名”输入框中输入用户名和密码

2. 点击登录按钮

3. 重复上述步骤4次 1-3次产生效果1，第4次产生效果2

4. 等待10分钟

5. 再次尝试步骤1、2，产生效果3

##### 预期结果

1. 效果1：

![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-15-17-13-24-image.png)

2. 效果2：

![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-15-17-13-52-image.png)

3. 效果3：登录成功

#### 9. 账号密码登录

##### 预置条件

1. 关闭多因子认证

2. 用户已注册account

3. account未被锁定

4. 用户名和密码

##### 步骤描述

1. 在“用户名”输入框中输入用户名和密码

2. 点击登录按钮

##### 预期结果

1. 输入用户名无效，提示：

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-15-16-48-35-image.png)

2. 输入正确密码，成功登录

3. 输入错误密码，登录失败，提示：![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-15-16-48-35-image.png)



#### 11. 微信扫码登录

##### 预置条件

1. 用户成功登录系统

2. account未绑定微信扫码

##### 步骤描述

1. 用户首次登录系统，弹出微信扫码绑定页 或点击微信扫码绑定页

2. 使用微信扫码

3. 在微信中点击绑定

4. 系统返回绑定成功提示

5. 用户再次登录系统，点击微信扫码登录

6. 用户使用微信扫码

7. 系统验证用户身份并成功登录 出现效果1

8. 在设置中选择解绑微信

9. 点击确认

10. 在微信中确认解绑

11. 系统返回解绑成功提示  

12. 用户再次登录系统，点击微信扫码登录

13. 系统提示用户未绑定微信 出现效果2

##### 预期结果

效果1：登录成功

效果2：登录失败，提示：

![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-15-17-04-11-image.png)

#### 12. 短信登录

##### 预置条件

1. 关闭多因子认证

2. 用户已注册account

3. account未被锁定

4. account已绑定手机号

##### 步骤描述

1. 输入手机号或者用户名

2. 点击发送验证码按钮

3. 输入验证码

4. 点击确认

##### 预期结果

若输入验证码正确，提示登录成功

若输入验证码错误，则登录失败，提示：

![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-15-17-19-32-image.png)

#### 5. 短信登录[验证码过期]

##### 预置条件

1. 关闭多因子认证

2. 用户已注册account

3. account未被锁定

4. account已绑定手机号

##### 步骤描述

1. 输入手机号或者用户名

2. 点击发送验证码按钮

3. 等待5分钟

4. 输入验证码

5. 点击确认

##### 预期结果

登录失败，提示：

![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-15-17-19-59-image.png)

#### 13. 微信公众号绑定

##### 预置条件

1. 用户成功登录系统

2. account未绑定公众号

##### 步骤描述

1. 登录系统绑定页

2. 点击微信公众号绑定

3. 微信扫码

4. 微信关注公众号

##### 预期结果

绑定成功

#### 7. 公众号验证码登录

##### 预置条件

1. 关闭多因子认证

2. 用户已注册account

3. account未被锁定

4. account已绑定微信公众号

##### 步骤描述

1. 点击公众号验证码登录

2. 点击发生验证码按钮

3. 输入验证码

4. 点击确认

##### 预期结果

登录成功

##### 实际结果

登录失败，步骤2出现错误：INVALID_CREDENTIALS

#### 14. 短信弱验证

##### 预置条件

1. 关闭多因子认证

2. 用户已注册account

3. account未被锁定

4. account已绑定手机号

##### 步骤描述

1. 登录页点击短信弱验证

2. 输入手机号

3. 点击发送验证码按钮

4. 输入验证码

5. 点击确认

##### 预期结果

登录成功

##### 实际结果

登录失败，跳转到绑定第三方因子界面，点击确认并继续按钮没反应，绑定其他第三方因子异常

#### 15. 微信扫码绑定冲突测试

##### 预置条件

1. 两个登录成功的Account，A1和A2

2. A1和A2都未绑定微信扫码

##### 步骤描述

1. A1登录系统

2. A1绑定微信1 产生效果1

3. A2登录系统

4. A2绑定微信1 产生效果2

5. 通过微信1扫码登录 产生效果3

6. A2解绑微信1

7. 通过微信1扫码登录 产生效果4

8. 登录A1查看绑定的微信1 产生效果5

##### 预期结果

A1绑定微信1后，当A2尝试绑定微信1时会受到提示：该微信已绑定账号

##### 实际结果

1. 效果1：A1绑定微信1成功

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-15-17-32-41-image.png)

2. 效果2：A2绑定微信1成功

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-15-17-35-06-image.png)

3. 效果3：微信1扫码登录成功，account为A2

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-15-17-37-28-image.png)

4. 效果4：没有Account绑定微信1

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-15-17-39-36-image.png)

5. 效果5：A1绑定的微信1被覆盖

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-15-17-41-34-image.png)

![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-14-23-41-image.png)

#### 22. 生物识别认证[微信生物认证]

##### 预置条件

1. 关闭多因子认证

2. 用户已登录成功

##### 步骤描述

1. 在绑定页面点击生物识别-编辑按钮

2. 点击注册微信生物认证按钮

3. 微信扫码

4. 点击微信公众号推送消息

5. 微信中点击验证身份按钮

6. 进行指纹或人脸验证 产生效果1

7. 手动转到登录页

8. 点击生物识别认证

9. 点击开始认证按钮

10. 点击微信公众号推送的消息

11. 点击验证身份按钮

12. 进行验证 产生效果2

##### 预期结果

1. 效果1：

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-10-17-08-image.png)

2. 效果2:

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-10-19-10-image.png)

#### 23. 生物识别认证[设备内置生物认证]

##### 预置条件

1. 关闭多因子认证

2. 用户已登录成功

##### 步骤描述

1. 在绑定页面点击生物识别-编辑按钮

2. 点击开始注册按钮

3. 根据弹出提示创建通行密钥 产生效果1

4. 手动转到登录页

5. 点击生物识别认证

6. 点击开始认证按钮

7. 根据弹出框进行身份验证

##### 预期结果

1. 效果1：

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-14-15-08-image.png)

2. 步骤7若验证成功，则登录成功

#### 24. 安全令牌认证[苹果手机]

##### 预置条件

1. 关闭多因子认证

2. 用户已登录成功

3. 两个系统是ios16以上的苹果手机 IPhone1和IPhone2

##### 步骤描述

1. 在绑定页面点击安全令牌-绑定按钮

2. 点击开始注册按钮

3. 使用IPhone1相机扫码出现的二维码

4. 手机点击存储安全密钥并验证 产生效果1

5. 手动转到登录页

6. 点击FIDO2安全密钥按钮

7. 点击开始认证按钮

8. 在弹出框点击 使用手机、平板电脑或安全密钥 按钮

9. 使用IPhone1相机扫码出现的二维码

10. 手机点击通行秘钥登录

11. 进行验证

12. 在绑定页面点击备用令牌-绑定按钮

13. 点击开始注册按钮

14. 使用Iphone2相机扫码出现的二维码

15. 手机点击存储安全密钥并验证 产生效果2

16. 在绑定页面点击安全令牌-解绑按钮 产生效果3

17. 使用Iphone2重复步骤5-11 产生效果4

##### 预期结果

1. 效果1:

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-10-24-36-image.png)

2. 步骤11 登陆成功

3. 效果2：

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-10-40-08-image.png)

4. 效果3：

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-10-47-17-image.png)

5. 效果4：登陆成功

#### 25. 国密密钥认证登录

##### 预置条件

1. 关闭多因子认证

2. 用户已登录成功

3. 国密密钥USB

##### 步骤描述

1. 在绑定页面点击国密密钥-绑定按钮

2. 页面中点击下载mplugins认证插件（若已下载，则跳过）

3. 按照步骤安装mplugin

4. 插入国密密钥USB 产生效果1

5. 点击确定按钮 产生效果2

6. 手动跳转到登录页

7. 点击国密密钥登录按钮 产生效果3

8. 点击确定按钮

##### 预期结果

1. 效果1：

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-11-36-20-image.png)

2. 效果2：

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-11-36-50-image.png)

3. 效果3：

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-11-37-45-image.png)

#### 26. 密码多因子认证[国密密钥二次验证]

##### 预置条件

1. 开启多因子认证

2. 第二认证方式开启微信扫码

3. 用户已注册account

4. account未被锁定

5. account已绑定国密密钥

6. 国密密钥USB

##### 步骤描述

1. 点击密码登录

2. 在“用户名”输入框中输入用户名和密码

3. 点击登录按钮

4. 跳转到多因子认证界面

5. 点击国密密钥登录按钮 产生效果1

6. 点击确认按钮 产生效果2

##### 预期结果

1. 效果1：

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-11-50-31-image.png)

2. 效果2：

   ![](D:\kafka\senhe_docs\vac测试\markdown_picture\2024-10-16-11-51-04-image.png)

3. 结果是登录成功

#### 16. 密码多因子认证[短信二次验证]

##### 预置条件

1. 开启多因子认证

2. 第二认证方式开启短信验证码

3. 用户已注册account

4. account未被锁定

5. account已绑定手机号

##### 步骤描述

1. 点击密码登录

2. 在“用户名”输入框中输入用户名和密码

3. 点击登录按钮

4. 跳转到多因子认证界面

5. 点击使用短信登录按钮

6. 点击发生验证码按钮

7. 填写验证码

8. 点击确认按钮

##### 预期结果

1. 若密码正确：则跳入到多因子认证界面：

   

2. 若密码错误，则提示：

   

3. 若短信验证码错误，则提示：

   

4. 若验证码正确，则登录成功

#### 17. 密码多因子认证[微信扫码二次验证]

##### 预置条件

1. 开启多因子认证

2. 第二认证方式开启微信扫码

3. 用户已注册account

4. account未被锁定

5. account已绑定微信扫码

6. 启动微信扫码登录方式

##### 步骤描述

1. 点击密码登录

2. 在“用户名”输入框中输入用户名和密码

3. 点击登录按钮

4. 跳转到多因子认证界面

5. 点击使用微信扫码登录按钮

6. 微信扫码授权

7. 点击确认按钮

##### 预期结果

1. 若密码正确：则跳入到多因子认证界面：

   

2. 若密码错误，则提示：

   

#### 18. 微信扫码多因子认证[密码二次验证]

##### 预置条件

1. 开启多因子认证

2. 用户已注册account

3. account未被锁定

4. account已绑定微信扫码

5. 设置中关闭微信免密码登录

6. 启动微信扫码登录方式

##### 步骤描述

1. 点击微信扫码登录

2. 使用微信扫码

3. 微信中点击授权确认

4. 跳转到多因子认证界面

5. 点击密码验证 产生效果1

6. 输入用户名和密码

7. 点击登录

##### 预期结果

1. 效果1：

   

2. 若步骤6密码错误，则步骤7提示：

   

3. 若步骤6密码正确，则步骤7的结果为登陆成功

#### 19. 微信扫码多因子认证[短信二次验证]

##### 预置条件

1. 开启多因子认证

2. 第二认证方式开启短信验证码

3. 用户已注册account

4. account未被锁定

5. account已绑定微信扫码

6. account已绑定手机号

7. 设置中关闭微信免密码登录

8. 启动微信扫码登录方式

##### 步骤描述

1. 点击微信扫码登录

2. 使用微信扫码

3. 微信中点击授权确认

4. 跳转到多因子认证界面

5. 点击短信验证 产生效果1

6. 点击发送验证码

7. 填写验证码

8. 点击登录确认

##### 预期结果

1. 效果1：

   

2. 若步骤7的验证码正确，则步骤8结果为登录成功

3. 若步骤7的验证码错误，则步骤8提示:

   

#### 20. 微信扫码多因子认证[微信公众号二次验证]

##### 预置条件

1. 开启多因子认证

2. 第二认证方式开启微信公众号验证码

3. 用户已注册account

4. account未被锁定

5. account已绑定微信扫码

6. account已绑定微信公众号

7. 设置中关闭微信免密码登录

8. 启动微信扫码登录方式

##### 步骤描述

1. 点击微信扫码登录

2. 使用微信扫码

3. 微信中点击授权确认

4. 跳转到多因子认证界面

5. 点击公众号验证 产生效果1

6. 点击发送验证码 产生效果2

7. 填写验证码

8. 点击登录确认

##### 预期结果

1. 效果1：

   

2. 效果2:

   

#### 21. 微信扫码多因子认证[国密密钥二次验证]

##### 预置条件

1. 开启多因子认证

2. 第二认证方式开启国密密钥认证

3. 用户已注册account

4. account未被锁定

5. account已绑定微信扫码

6. account已绑定国密密钥验证

7. 设置中关闭微信免密码登录

8. 启动微信扫码登录方式

9. 国密密钥USB

##### 步骤描述

1. 点击微信扫码登录

2. 使用微信扫码

3. 微信中点击授权确认

4. 跳转到多因子认证界面

5. 点击国密密钥按钮 产生效果1

6. 插入国密密钥USB 产生效果2

7. 输入国密密钥密码

8. 点击登录确认产生效果3

##### 预期结果

1. 效果1：

   

2. 效果2：

   

3. 效果3：

#### 27. 国密密钥多因子认证[密码二次验证]

##### 预置条件

1. 开启多因子认证

2. 用户已注册account

3. account未被锁定

4. account已绑定国密密钥

5. 国密密钥USB

6. 免密码登录关闭国密密钥

##### 步骤描述

1. 插入国密密钥USB

2. 转到登录页

3. 点击国密密钥按钮

4. 输入国密密钥密码

5. 点击确认按钮

6. 页面跳到多因子验证界面

7. 点击密码登录按钮

8. 输入密码

9. 点击登录按钮

##### 预期结果

1. 步骤9，若输入密码错误，则登录失败

2. 步骤9，若输入密码正确，则登录成功
