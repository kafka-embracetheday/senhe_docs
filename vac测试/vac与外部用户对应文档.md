#### 1. 模型概念

##### 1. 外部实体 ExternalEntity 

```
实体类对应的代码vac\domain\directory\entity\external.py中的：class ExternalEntity(BaseTable)
[137]该实体包含了外部用户文档中的字段信息，返回新实体方法、resource_urn字段的链接以及删除链接还有union_id的设置。
```

##### 2. 本地用户Account

```
实体类对应的代码vac\domain\directory\entity\account.py中的：class Account(IdentityProtocol, BaseTable)
[45]Account: 该实体包含了外部文档中的字段信息
[111]create_account: 方法对account进行初始化并返回
[139]modify_expiry_time: 修改用户过期时间 无法修改已归档的用户的过期时间
[145]archive：将用户设置为已归档 self.archived = True
[152]confirm：确认账户的状态
[159]disable：将用户设置为不可用
[163]assert_valid_login_name：验证是否为合法的用户名
[171]assert_valid_fullname：验证是否为合法的姓名
[176]sanitize_fullname：清理全名，作用是去除名字中的字符
[179]assign_login_name：分配登录名
[199-265]verify_passwd、enforce_password_history、_set_password、change_password分别为验证密码、密码重复性检查、设置密码、修改密码
```

##### 3. 临时用户

```
实体类对应的代码vac\domain\directory\entity\external.py中的：class ExternalIdentity(IdentityProtocol, BaseTable)
[137]该实体包含了外部用户文档中的字段信息，返回新实体方法、resource_urn字段的链接以及删除链接还有union_id的设置。
```

##### 4. 用户组管理

```
实体类对应的代码vac\domain\directory\entity\group.py中的：Group(BaseTable)，包括验证用户名是否可用、创建组、归档等
用户组管理对应AccountGroup(BaseTable)
```

##### 5. source认证来源

```
实体类对应的代码vac\domain\directory\entity\group.py中的：Group(BaseTable)，包括验证用户名是否可用、创建组、归档等
用户组管理对应AccountGroup(BaseTable)
```



#### 2. 项目包

##### 1. 顺序

vac/facede/web/  - >  vac/application/  ->  vac/domain/directory/service  ->  vac/infra/

##### 2. 作用



#### 3. 接口

##### 1. 创建account

```python
路径：vac/facade/web/account.py
入参：
{"disabled":false,"role_name":"device_user","remarks":[],"mobile_verified":false,"login_name":"testcase","fullname":"testcase","password":"ASdf12!@","generate_password":false}


@post('/api/account/create')
@api
def create_account():
    # 从表单中获取数据
    payload = json.loads(request.forms['account'])
    files = request.files
	
    # 获取用户过期时间
    expiry_time = payload.pop('expiry_time', None)
    # 如果expiry_time不为空则转换格式并存储到expiry_time
    if expiry_time:
        expiry_time = datetime.strptime(f'{expiry_time} 23:59:59', '%Y-%m-%d %H:%M:%S')

    # 是否生成密码字段
    generate_password = payload.pop('generate_password', False)
    # 如果生成密码为true以及前端没有传入mobile字段则返回异常
    if generate_password and 'mobile' not in payload:
        raise FacadeException('MobilePhoneIsEmpty')

    # 获取角色名
    role_name = payload.pop('role_name', None)
    # 将表单数据以及操作名称放到context
    with operation_context(
            action_name='account:CreateAccount',
            request=payload) as context:

        # 如果传入文件
        for name, file in files.items():
            filename = s3.put_bucket_object(
                bucket_name='upload',
                io_file=file.file,
                content_type=file.content_type,
                metadata={
                    'filename': file.raw_filename,
                })
            payload['remarks'][int(name.removeprefix('upload'))]['filename'] = filename

        # 获取当前用户的身份
        identity = SessionService.get_current_identity()
        #走创建用户流程
        account: Account = AccountApplication.create_account(
            # 传参
            # KnownSource是一个枚举，KnownSource.CONSOLE是 控制台创建
            source_urn=KnownSource.CONSOLE,
            expiry_time=expiry_time,
            login_name=payload.pop('login_name', None),
            password=payload.pop('password', None),
            attributes={
                key: value for key, value in payload.items() if value
            },
            generate_password=generate_password,
            role_name=role_name,
            creator_id=identity.account_id,
        )

        # 如果开启了三权分立模式，并且账号创建完成后是未激活状态，则自动发起激活账号审批流程
        if config.power_separated() and account.status is AccountStatus.UNCONFIRMED:
            WorkflowService.start_process('urn:process/confirm_account:v1', {
                'account_id': account.id,
                'fullname': account.fullname,
                'mobile': account.mobile,
                'expiry_time': account.expiry_time,
            })

        context.yield_result({
            "account_id": account.id,
            "login_name": account.login_name,
            "fullname": account.fullname,
        })

    return account.as_dict(['id'])


```

```python
	路径：vac/application/account.py
    
    
    AUTOGEN_TEMPLATE = '您的 {system_name} 用户已成功创建，' \
                       '用户名『{login_name}』，初始密码『{password}』，请勿泄漏【IAM】'
    ADMIN_RESET_TEMPLATE = '管理员已为您重置密码，新密码为『%s』，请妥善保管【IAM】'
    CHANGE_PASSWORD_TEMPLATE = '管理员已为您重置密码，新密码为『{new_password}』，请妥善保管【IAM】'

    # 类方法
    @classmethod
    # 事务操作
    @transactional
    def create_account(cls, source_urn: str | KnownSource, expiry_time: datetime,
                       login_name: str = None, password: str = None,
                       attributes: dict[str, str] = None, generate_password: bool = False,
                       role_name: str = None, creator_id: int = None) -> Account:

        # 看source_urn是否是KnowSource的子类，也就是说是否是已知的创建来源
        # isinstance的作用是 查一个对象是否是特定类或其子类的实例。
        if isinstance(source_urn, KnownSource):
            source_urn = source_urn.name

        # 如果生成密码为true
        if generate_password:
            # 因为接受表单数据时将payload字段都放入到了attributes中
            # 如果不存在mobile返回异常
            if not attributes.get('mobile') or not attributes.get('mobile_verified'):
                raise FacadeException('MobileNotVerified')
			
            # 生成随机密码
            password = SecurityService.generate_password(
                login_name=login_name
            )

        account = DirectoryService.create_account(
            source_urn=source_urn, expiry_time=expiry_time,
            login_name=login_name, password=password,
            attributes=attributes, creator_id=creator_id,
        )

        # 如果role_name不为空，则给该用户分配角色
        if role_name:
            AuthorizationService.assign_role(
                role_name=role_name, assignee_urn=account.urn(),
            )

        # 如果generate_password=true，则生成短信并发送
        if generate_password:
            MessageService.send_sms_message(
                template=dog.SmsTemplate.InitialPassword,
                ttl=86400,
                mobile=int(attributes['mobile']),
                params={'system_name': '', 'login_name': login_name, 'password': password},
                scene='create_account',
                recipient_urn=account.urn(),
            )

        return account
```

```python
 路径：vac/application/account.py
    
    @classmethod
    @transactional
    def create_account(cls, source_urn: str,
                       expiry_time: Optional[datetime] = DEFAULT_EXPIRY_TIME,
                       login_name: str = None, password: str = None, creator_id: int = None,
                       unique_id: str = None, attributes: dict = None, system_init: bool = False) -> Account:

        attributes = attributes.copy() if attributes else {}
        inline_attributes = {
            "mobile": attributes.pop('mobile', None),
            "mobile_verified": attributes.pop('mobile_verified', False),
            "email": attributes.pop('email', None),
            "email_verified": attributes.pop('email_verified', False),
            "fullname": attributes.pop('fullname', None),
            "disabled": attributes.pop('disabled', False),
        }

        fullname = inline_attributes['fullname']
        if fullname:
            Account.assert_valid_fullname(fullname)

        if inline_attributes['mobile_verified']:
            mobile = inline_attributes['mobile']
            if not mobile:
                raise DomainException('MobileVerifiedEmptyValue')

            if not valid_mobile(mobile):
                raise DomainException('InvalidMobileNumber')

        if inline_attributes['email_verified'] and not inline_attributes['email']:
            raise DomainException('EmailVerifiedEmptyValue')

        attributes["security"] = {
            "allowed_ips": attributes.pop('allowed_ips', []),
        }

        account = Account.create_account(
            expiry_time=expiry_time,
            source_urn=source_urn,
            unique_id=unique_id,
            **inline_attributes,
            attributes={key: value for key, value in attributes.items() if key in cls.MODIFIABLE_ATTRIBUTES},
            creator_id=creator_id,
            system_init=system_init,
        )
        # 生成到数据库
        AccountRepository.add(account)

        if account.mobile and account.mobile_verified:
            BindingService.make_binding(
                identity_urn=account.urn(),
                name=KnownBindings.MOBILE,
                key=account.mobile,
                source_urn=source_urn,
            )

        if login_name:
            account.assign_login_name(
                login_name=login_name,
                source_urn=source_urn,
            )

            if password:
                SecurityService.validate_password(
                    password=password, login_name=login_name
                )
                account.set_initial_password(password)

        if WorkflowService.should_account_unconfirmed():
            account.status = AccountStatus.UNCONFIRMED

        AccountRepository.merge(account)
        return account
```





##### 2. 登录

```python
vac/facede/web/auth/define.py

@get('/api/login')
def login_page():
    # 尝试恢复当前的登录状态
    LoginState.resume()
	
    # 如果需要多因子认证 并且多因子认证没初始化 则重定向到认证界面
    if passbox.is_required() and not passbox.is_initiated():
        LoginState.mark_modified()
        return LoginState.pause_redirect('/api/passbox')

    requirements = Requirements.from_serialized(request.query.get('r'))
    principle = SessionService.get_current()

    # check if match requirements
    # 获取之前的登录信息，如果存在则置空
    if principle and requirements and not requirements.match(principle):
        SessionService.clear_current()
        principle = None

    if principle:
        if principle.roles:
            from vac.facade.web.auth.challenge.checkup import SecurityCheckup
            # 进行安全检查
            # 如果检查的时间间隔小于当前时间减去上次检查的时间，则重定向到绑定页
            # 如果用户存在宽限期内，则重定向到绑定页
            SecurityCheckup.maybe_security_checkup()

            # 如果设置了强制绑定微信，则跳到绑定微信页面
            if RedisSettingRepository.get_setting('authn.force_bind_wechat'):
                identity = SessionService.current_identity()
                # 如果没有微信分享，并且
                if not identity['wechat_shared'] and not request.get_cookie('_defer_force_wechat'):
                    redirect('/api/login/enroll/wechat?forced=1')

        return_url = MantisSharedProcessProviderDriver.recover_from_login()
        if return_url and return_url != '/':
            redirect(return_url)

        # 对身份进行验证
        if not principle.roles:
            # 如果是vxp登录，则转到根目录
            if is_vxp():
                # goto nav page
                return redirect('/')

            # external or local user without roles,
            # which doesn't have right to use VAC
            # 没有角色的外部用户或者本地用户无权使用vac，转到绑定页
            return redirect('/api/login/checkup')
        else:
            return redirect('/')

    # handles continuation
    # 如果身份不存在 但是登录状态的身份urn存在，则清空登录状态的urn
    identity = LoginState.identity
    if not identity and LoginState.identity_urn:
        LoginState.clear()

    # 如果身份存在但是挑战也存在，则持续挑战
    # 对应外部用户的
    challenges = LoginState.challenges
    if identity and challenges:
        return ChallengeManager.continue_challenge(
            identity=identity, completed=challenges,
        )

    # fresh login session from here.
    # handles next arg
    # 开启一个新会话
    LoginState.fill_next()
    LoginState.fill_requirements(requirements)

    # none challenge completed.
    sources = None
    # 该函数是从cookie中获取上次登录的信息
    if last_login := recover_last_login():
        sources = last_login['sources']

        if not identity:
            try:
                identity = urn.UrnNamedResource.from_urn(last_login['identity_urn'])
                if identity.archived:
                    # 如果last_login的账号已被删除，则清空identity和last_login
                    identity = None
                    clear_last_login()
            except DomainException as err:
                if err.code not in ('AccountNotFound', 'ExternalIdentityNotFound'):
                    raise

                clear_last_login()

                
    if identity:
        # 如果身份确认，从redis获取选定的来源
        if selected_source := RedisSettingRepository.get_setting('authn.selected_source'):
            # 使用选定的来源进行获取到认证来源
            source = RedisSourceRepository.load_source(selected_source)
            # 进行挑战
            return ChallengeManager.start_challenge(
                identity=identity, preferred=[[selected_source, source.adapter_type.name]],
                local_first=False, requirements=requirements,
            )
        else:
            return ChallengeManager.start_challenge(
                identity=identity, preferred=sources or [],
                requirements=requirements,
            )

    # we don't know who will be challenged.
    # in China, identity-first flow doesn't fit
    # 开启一个挑战
    ChallengeManager.start_identify_challenge(requirements=requirements)

    # # if DeviceKeyRepository.has_device_keys(account_id=account.id, key_type=KeyType.FIDO2):
    # #     return State.pause_redirect('/api/login/browser-capability', next='fido2_login')
    #
    # login_settings = RedisSettingRepository.get_setting('login')
    # if login_settings.get('identity_first'):
    #     return redirect(f'{MOUNTING_PATH}/api/login/password')

```



