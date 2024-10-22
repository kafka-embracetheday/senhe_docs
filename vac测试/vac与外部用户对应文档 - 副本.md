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
    # 挑战最后返回一个...
    # 对应外部用户的3.发现没有A - 保存EE.id - 继续触发认证 - 直到能获得到A
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

```python
路径：vac/facade/web/auth/api.py

返回参数：
{
    "status": "success",
    "code": "ok",
    "data": {
        "identity": {
            "source_id": 0,
            "name": "IH2d0woxOb50",
            "claims": {
                "status": "CONFIRMED",
                "login_name": "testcase",
                "fullname": "testcase",
                "mobile": "18186841163",
                "mobile_verified": "2024-10-22 10:32:01",
                "email": null,
                "email_verified": null,
                "unique_id": "IH2d0woxOb50",
                "avatar_url": "https://thirdwx.qlogo.cn/mmopen/vi_32/GN3FDkHxecKenwn5C2Z1B4OqeiakycMF70UR1ErIaMmKGnnbwbXRbBVaxPsLptITZPWxpU1iab4aalAUuM6DKEe4fK5eMFvopr4z7maqLUSMs/132",
                "groups": [],
                "group_ids": [],
                "created": "2024-10-21",
                "source_name": "\u63a7\u5236\u53f0\u521b\u5efa"
            },
            "urn": "urn:account/4",
            "account_id": 4,
            "group_ids": []
        },
        "roles": [
            "device_user"
        ],
        "elevation": null,
        "passbox": true,
        "product": "VAC",
        "temporary_permission": null
    }
}

# 获取当前用户信息
@get('/api/current')
@api
def current_user():
    # 获取当前会话用户信息，如果存在则获取身份信息
    principle = SessionService.get_current()
    identity = principle and principle.identity
    if principle:
        # 获取并计算提权时间
        elevation = principle.context.get('elevation')
        if elevation:
            elevation['timeout'] = elevation['at'] + RedisSettingRepository.get_setting('elevation.session_lifetime')
            if elevation['timeout'] < time.time():
                elevation = None

        # 获取到roles信息，如果当前模式为vxp模式并且request header不是vxp模式，清空roles列表
        roles = principle.roles
        if config.is_vxp() and request.get_header('X-Vxp-Admin') != 'yes':
            roles = []

        temporary_permission = None
        if config.power_separated():
            undone_processes = set()
            undone_operation_processes, _ = ProcessInstanceRepository.find(
                result='undone',
                process_urn='urn:process/apply_operation_session:v1'
            )

            for process in undone_operation_processes:
                if process.payload['account_id'] == identity.account_id:
                    undone_processes.add('apply_operation_session')

            undone_system_setting_processes, _ = ProcessInstanceRepository.find(
                result='undone',
                process_urn='urn:process/apply_sysconfig_session:v1'
            )

            for process in undone_system_setting_processes:
                if process.payload['account_id'] == identity.account_id:
                    undone_processes.add('apply_sysconfig_session')
			
            # 临时权限赋予
            temporary_permission = {
                'operation': AuthorizationService.get_temporary_permission_remainder(
                    account_urn=SessionService.current_identity_urn(),
                    temporary_permission='operation'
                ),
                'system_setting': AuthorizationService.get_temporary_permission_remainder(
                    account_urn=SessionService.current_identity_urn(),
                    temporary_permission='system_setting'
                ),
                'device_user_login': AuthorizationService.get_temporary_permission_remainder(
                    account_urn=SessionService.current_identity_urn(),
                    temporary_permission='device_user_login'
                ),
                'undone_processes': undone_processes,
            }
		# 已登录用户返回
        return {
            'identity': identity.__dict__,
            'roles': roles,
            'elevation': elevation,
            'passbox': passbox.is_initiated(),
            'product': config.get_conf('app.product_name'),
            'temporary_permission': temporary_permission,
        }
    else:
        # 未登录用户返回
        return {
            'identity': None,
            'roles': [],
            'elevation': None,
            'passbox': passbox.is_initiated(),
            'product': config.get_conf('app.product_name'),
        }

```



##### 3. 绑定微信

```python
路径：vac/facade/web/auth/enrollment/wechat.py
对应文档：b.场景2：enroll_externally - 先登录系统，再绑定新的 [外部] 认证⽅式

@get('/api/login/enroll/wechat/session')
@login_required
@api
@transactional
def wechat_shared_bind_session():
    
   	# 获取传来的session_id
    session_id = request.query.get('session_id')
    # 验证session_id，如果不正确则抛出异常
    validate_session_id(session_id)

    # 如果用户属于授予状态
    if WechatSharedAdapter.instance.delegated:
        # 通过session_id获取到用户信息
        user = dog.wechat_session2user(session_id)
    else:
        # 查询redis中该session_id的状态
        content = REDIS_CONN.get(f"SESSION:wechat:{session_id}")
        # 如果不存在该session_id
        if not content:
            raise FacadeException('SessionNotReady')
		
        # redis删除该session_id
        REDIS_CONN.delete(f"SESSION:wechat:{session_id}")
        # 如果redis中的session_id状态为已经被扫码，则抛出异常
        if content == b'SCANNED':
            raise FacadeException('QrcodeScanned')
		
        # 进行转换json操作
        user = json.loads(content)

    # 将信息赋值 将微信用户与当前登录用户绑定
    WechatSharedAdapter.bind(
        identity=SessionService.current_identity(),
        wechat_user=user,
    )

    # 进行记录。openid和nickname用来追溯
    AuditService.record_profile(
        action_name='profile:BindWechat',
        request={'nickname': user['nickname'], 'openid': user['openid']},
    )

```

```python
@classmethod
def bind(cls, wechat_user: dict, identity: IdentityProtocol):
    cls.unbind(openid=wechat_user['openid'])

    identity['wechat_shared'] = wechat_user
    BaseRepository.merge(identity)

    BindingService.make_binding(
        name=KnownBindings.WECHAT_SHARED_OPENID,
        key=wechat_user['openid'],
        identity_urn=identity.urn(),
        override_identity=True,
    )
```

##### 4. 绑定手机号

```python
路径：vac/facade/web/auth/enrollment/sms.py

@post('/api/login/enroll/sms')
@render('login.enroll.sms')
@transactional
def sms_bind_modify_action():
    # 如果没有当前状态则刷新会话
    identity = SessionService.current_identity()
    if not identity:
        return LoginState.restart()

    # for exception handling
    add_render_context(
        mobile=identity['mobile'], sent=False,
        display_name=identity.display_name,
    )

    # 如果当前的操作为取消则转到绑定页
    action = request.forms['action']
    if action == 'cancel':
        return redirect('/api/login/checkup')

    mobile = request.forms['mobile']
    if not valid_mobile(mobile):
        raise FacadeException('InvalidMobileNumber')

    if mobile == identity['mobile']:
        raise FacadeException('MobileIsSame')

    # 如果操作为发送验证码 则生成验证码发送
    if action == 'send':
        code, generated = sms.generate_code(
            domain='enroll', mobile=mobile,
        )

        if generated:
            MessageService.send_sms_message(
                mobile=int(mobile),
                template=dog.SmsTemplate.CodeForLogin,
                params={
                    'system_name': passbox.license_name(),
                    'code': code,
                    'ttl': 5,
                },
                ttl=300,
                scene='change_auth',
                recipient_urn=identity.urn()
            )

        return {
            'new_mobile': mobile,
            'sent': True,
        }
        
    # 如果操作为验证 则验证验证码，并使用SmsAdapter绑定手机号与身份 并记录
    elif action == 'verify':
        add_render_context(sent=True, new_mobile=mobile)

        code = request.forms['code']
        if not code or len(code) != 6 or not code.isdigit():
            raise FacadeException('InvalidCodeFormat')

        ok = sms.consume_code(
            domain='enroll', mobile=mobile, code=code,
        )
        if not ok:
            raise FacadeException('InvalidCode')

        SmsAdapter.bind(mobile, identity)
        AuditService.record_profile(
            action_name='profile:ChangeMobile',
            request={'mobile': mobile},
        )
        return redirect('/api/login/checkup')

    return redirect(None)
```

##### 5. 密码登录

```python
路径：vac/facade/web/auth/challenge/password.py

@post('/api/login/password')
@render('login.password')
def login_password_page():
    # 尝试恢复当前登录状态
    LoginState.resume()
    source = LoginState.assert_challenge(AdapterType.PASSWORD)

    # 如果操作为not_me，则开始挑战
    if request.forms.get('action') == 'not_me':
        ChallengeManager.start_identify_challenge(requirements=LoginState.requirements)
        return

    # 获取密码并解密
    encrypted = request.forms.get('encrypted')
    if not encrypted:
        raise FacadeException('EmptyPassword')

    password = util.decrypt_password(LoginState['cc']['ek'], encrypted)
	
    # 获取身份信息
    identity: IdentityProtocol = LoginState.identity
    # 获取登录名 如果存在，并对用户名进行清洗
    login_name = request.forms.get('username')
    if login_name:
        login_name = login_name.strip()

    # 如果用户名不为空并且用户名不合法，则记录并抛出异常
    if login_name and not valid_login_name(login_name):
        AuditService.record_authn_unknown_identity(
            session_id=LoginState.session_id,
            method_type=AdapterType.PASSWORD,
            request={'username': login_name},
        )
        # FIXME security lock IP
        raise FacadeException('InvalidLoginName')
	#如果无身份信息
    if not identity:
        # 如果无login_name，抛出异常
        if not login_name:
            raise FacadeException('EmptyLoginName')

        # 对用户名密码进行验证
        SecurityService.check_identity_locked(f'password/{login_name}')
        # 获取该用户名绑定的unique_binding
        binding = UniqueBindingRepository.find_binding(
            name=KnownBindings.LOGIN_NAME,
            key=login_name,
        )
        # 将unique_binding信息赋值到身份
        identity = binding and binding.load_identity()
	
    # 如果为空
    if not identity:
        # 进行外部验证
        return finish_external_sources(login_name=login_name, password=password)
	
    # 判断identity是Account类型 
    assert isinstance(identity, Account)
    # 检查该用户的锁定状态 分为AccountLocked、IPLocked
    SecurityService.check_identity_locked(identity.urn())

    try:
        source.adapter.finish(identity=identity, password=password)
    except AuthnException as err:
        retry_count = SecurityService.record_authn_failure(identity=identity)
        AuditService.record_authn(
            session_id=LoginState.session_id,
            source=source,
            identity=identity,
            result_type=ResultType.FAILED,
            reason='IncorrectPassword'
        )
        raise FacadeException('PasswordMismatch', data={"retry_count": retry_count}) from err
    else:
        SecurityService.reset_authn_failure(identity.urn())

    # 完成挑战
    ChallengeManager.finish_challenge(
        source=source,
        identity=identity,
    )
```



```python
路径：vac/facade/web/auth/challenge/password.py
作用：完成外部来源认证

def finish_external_sources(login_name, password):
    try:
        # 确认来源 source是来源 result是结果
        source, result = try_password_sources(login_name=login_name, password=password)
    except AuthnException as err:
        retry_count = SecurityService.record_authn_failure(login_name=login_name)
        match err.code:
            # 如果密码错误 抛出异常
            case AuthenticationExceptionType.INVALID_CREDENTIALS:
                AuditService.record_authn(
                    session_id=LoginState.session_id,
                    identity=None,
                    source=err.source,
                    actor_identity=err.payload,
                    request={'username': login_name},
                    result_type=ResultType.FAILED,
                    reason='IncorrectPassword'
                )
            # 如果不知道身份错误 则记录
            case AuthenticationExceptionType.UNKNOWN_IDENTITY:
                AuditService.record_authn_unknown_identity(
                    session_id=LoginState.session_id,
                    method_type=AdapterType.PASSWORD,
                    request={'username': login_name},
                )
            case _:
                raise
		
        raise FacadeException('PasswordMismatch', data={"retry_count": retry_count})
	# 确保登录时的身份
    identity, _ = AuthnService.ensure_identity(
        source=source, result=result,
    )
    
    # 根据系统数据决定是否保存密码
    sso.maybe_save_password(
        source_id=source.id, login_name=login_name,
        password=password, identity=identity,
    )

    # 设置一下登录错误的次数
    SecurityService.reset_authn_failure(identity.urn())
    
    # 完成挑战
    ChallengeManager.finish_challenge(
        source=source,
        identity=identity,
        is_combined=True,
    )
```



```python
路径：vac/application/authn.py
作用：确保身份信息

@classmethod
def ensure_identity(cls, source: Source, result: AuthenticateResult, allow_external: bool = False) \
        -> tuple[Optional[IdentityProtocol], MappedIdentity]:
    """build or retrieve identity(IdentityProtocol) from external source"""

    # default mapper can be indicated in vac-fe
    mapped = source.mapper.map(name=result.name, claims=result.claims)

    # assign in-domain ID for foreign entities
    # 使用mapper将外部信息映射到本地，对应文档记录外部id到domain内，方便溯源
    cls._persist_entities(source=source, mapped=mapped)

    # discover linked account / EI
    # 匹配身份信息 其中prefer_account代表是否本地账户优先 对应文档中的 特殊场景处理3.绑定关系冲突解决
    identity = cls._locate_identity(source, mapped, prefer_account=not allow_external)

    # 如果可以注册account或者identity是Account类
    if source.register_account or isinstance(identity, Account):
        return cls._ensure_account(
            source=source, mapped=mapped, identity=identity,
        ), mapped
    # 如果register_account=false 并且 allow_external=false则返回EE外部实体
    elif not allow_external:
        return None, mapped
    # 如果register_account=false 并且 allow_external=true则返回EI临时用户
    else:
        return cls._ensure_external_identity(
            source=source, mapped=mapped, identity=identity,
        ), mapped
```

```python
路径：vac/application/authn.py
作用：将实体持久化到数据库

@classmethod
@transactional
def _persist_entities(cls, source: Source, mapped: MappedIdentity):
    relations = {
        EntityType.ORGANIZATION: mapped.organizations,
        EntityType.GROUP: mapped.groups,
        EntityType.ROLE: mapped.roles,
        EntityType.TAG: mapped.tags,
    }

    for entity_type, entities in relations.items():
        for entity in entities:
            entity.entity = ExternalEntityRepository.upsert(
                ExternalEntity.of(
                    source_id=source.id,
                    entity_type=entity_type,
                    mapped=entity,
                ),
            )

    mapped.entity.entity = ExternalEntityRepository.upsert(
        ExternalEntity.of(
            source_id=source.id,
            entity_type=EntityType.IDENTITY,
            mapped=mapped.entity,
            relations={
                'organizations': [organization.name for organization in mapped.organizations],
                'groups': [group.name for group in mapped.groups],
                'roles': [role.name for role in mapped.roles],
                'tags': [tag.name for tag in mapped.tags],
            }
        ),
    )
```

```python
路径：vac/domain/directory/repository/external.py
作用：将实体持久化到数据库，具体的插入代码。
对应文档：6.union_id：跨source关联EE-A

@classmethod
@transactional
def upsert(cls, entity: ExternalEntity) -> ExternalEntity:
    # load现有的实体
    existing: ExternalEntity = cls.load_by(
        source_id=entity.source_id,
        type=entity.type,
        name=entity.name,
        for_update=True,
    )
    
	# 如果不存在现有的实体
    if not existing:
        # 根据union_id加载一个新的实体
        existing_union: ExternalEntity = cls.load_by(
            source_id=entity.source_id,
            type=entity.type,
            name=entity.union_id,
        )
        # 如果该union_id没有对应实体，则清空
        if existing_union:
            # don't write union_id
            entity.set_union_id(union_id=None)

        # 新实体信息插入
        cls.add(entity)
        return entity
    else:
        # 更新现有的实体
        existing.original = entity.original
        existing.last_seen = entity.last_seen

        # 如果存在的实体绑定的union_id和新的union_id不同，则将union_id置为相同的一个
        if existing.union_id != entity.union_id:
            entity.set_union_id(entity.union_id)
		
        # 插入实体
        cls.merge(existing)

        return existing
```

```python
路径：vac/application/authn.py
作用：匹配身份信息

@classmethod
@transactional
def _locate_identity(cls, source: Source, mapped: MappedIdentity,
                     prefer_account: bool) -> Optional[IdentityProtocol]:
	
    # 获取EE
    external = mapped.entity.entity

    # 外部身份置为None
    identity: Optional[ExternalIdentity] = None

    # linked to account
    # 下面对应source来源认证的c三种认证结果
    resource_urn = external.resource_urn
    if resource_urn:
        # 如果该urn可以连接到account
        if Account.urn_isinstance(resource_urn):
            # 通过urn获取account
            account = Account.from_urn(resource_urn)
            # 如果account存在并且未被归档则返回account
            if account and not account.archived:
                return account
            else:
                # drop reference
                # 删除该urn与account的连接
                external.drop_link(
                    reason=LinkReason.TargetNotExistsOrArchived,
                )
        # linked to external identity
        # 如果可以连接到EI
        elif ExternalIdentity.urn_isinstance(resource_urn):
            identity = ExternalIdentity.from_urn(resource_urn)
            if identity and not identity.archived:
                # 如果不是本地account优先
                if not prefer_account:
                    return identity

                # wait for possible account binding
            else:
                # drop reference
                external.drop_link(
                    reason=LinkReason.TargetNotExistsOrArchived,
                )

                identity = None
        # linked to other entity
        # 连接到EE 抛出异常尚未实现
        elif ExternalEntity.urn_isinstance(resource_urn):
            raise NotImplemented
        else:
            assert False, f'unknown resource linked: {resource_urn}'

    # placed invitation
    # 查找绑定并连接unique_binding
    binding = UniqueBindingRepository.find_binding(
        name=f'source/{source.id}:name',
        key=external.name,
    )
    if account := binding and binding.load_identity():
        if not account.archived:
            external.make_link(
                resource=account,
                reason=LinkReason.InvitationAccepted,
            )

            return account

    # match by union_id
    # 如果存在union_id，则查找绑定的身份
    if union_id := mapped.entity.union_id:
        binding = UniqueBindingRepository.find_binding(
            name=KnownBindings.UNION_ID,
            key=union_id,
        )
		
        # 绑定account
        if account := binding and binding.load_identity():
            external.make_link(
                resource=account,
                reason=LinkReason.UnionIDMatched,
            )

            return account

    # fallback to possible EI
    return identity
```

```python
路径：vac/application/authn.py
作用：
对应文档：场景1：第⼀次认证，创建账号时ⅰ. authn_result - > register_account=True -> ensure_account


@classmethod
def _ensure_account(
        cls, source: Source, mapped: MappedIdentity,
        identity: IdentityProtocol = None) -> Account:

    # 获取外部实体EE
    external = mapped.entity.entity
    account = isinstance(identity, Account) and identity

    # 创建account
    if account:
        if account.source_urn == source.urn():
            # only allow source created account to modify
            account = DirectoryService.external_update_account(
                account=account,
                attributes=mapped.entity.claims,
                source_urn=source.urn(),
            )
        else:
            # log source_not_match
            pass
    else:
        account = DirectoryService.external_create_account(
            source_urn=source.urn(),
            external=external,
        )

        # link account_id
        # EE与account连接
        external.make_link(
            resource=account,
            reason=LinkReason.NewAccountCreated,
        )

    if mapped.entity.union_id:
        with ignore_code('ConflictedBinding', 'BindingNotOwnedBySource'):
            # don't override identity_urn
            BindingService.make_binding(
                name=KnownBindings.UNION_ID,
                key=mapped.entity.union_id,
                identity_urn=account.urn(),
                source_id=source.id,
                reason=LinkReason.LinkUnionIDToAccount,
            )

    cls._process_bindings(mapped=mapped, account=account, source=source)
    cls._link_relations(mapped=mapped, account=account, source=source)

    AccountRepository.merge(account)
    return account
```

##### 6.短信弱验证

```python
路径：vac/facade/web/auth/challenge/sms_weak.py
对应文档：
d.场景4：弱认证 authn_result - > allow_external=True, register_account=False -> ensure_external_identity -> EI

@post('/api/login/sms_weak')
@render('login.sms_weak')
def sms_weak_auth():
    # 尝试恢复登录状态
    LoginState.resume()
    source = LoginState.assert_challenge(AdapterType.SMS_WEAK)
    # 获取客户端ip
    client_ip = bottle_client_ip()
    if request.forms.get('action') == 'send':
        mobile = request.forms.get('login_name')
        if not mobile:
            raise FacadeException('EmptyMobile')

        # 去除+86和可能存在的空格
        mobile = mobile.removeprefix("+86").lstrip(' ')
        if not valid_mobile(mobile):
            raise FacadeException('InvalidMobileNumber')

        source.adapter.start(client_ip=client_ip, mobile=mobile)

        LoginState['cc']['mn'] = mobile
        LoginState['cc']['snt'] = True

        # 手机号写入cookie
        response.set_cookie(SMSWeakMethod.MOBILE_COOKIE_NAME, mobile)

        LoginState.mark_modified()
        return
    elif request.forms.get('action') == 'resend':
        mobile = LoginState['cc']['mn']
        source.adapter.start(client_ip=client_ip, mobile=mobile, action='resend')

        LoginState['cc']['snt'] = True

        LoginState.mark_modified()
        return

    # finish
    code = request.forms.get('code')
    if not code:
        raise FacadeException('MissingCode')

    try:
        # 完成外部用户的注册 allow_external=True
        identity, _ = AuthnService.finish_external(
            identity=LoginState.identity,
            source=source,
            response={
                'client_ip': client_ip,
                'mobile': LoginState['cc']['mn'],
                'code': code,
            },
            allow_external=True)
    except AuthnException as err:
        SecurityService.record_ip_failure()
        AuditService.record_authn(
            session_id=LoginState.session_id,
            source=source,
            identity=None,
            result_type=ResultType.FAILED,
            reason='InvalidCode'
        )
        if err.code is AuthenticationExceptionType.INVALID_CREDENTIALS:
            raise FacadeException('InvalidCode')
        raise
    else:
        # 记录登录失败次数
        SecurityService.reset_authn_failure(identity.urn())

    ChallengeManager.finish_challenge(
        source=source,
        identity=identity,
    )
```

```python
@classmethod
def finish_external(cls, identity: IdentityProtocol, source: Source,
                    response: dict, allow_external: bool = False) \
        -> tuple[Optional[IdentityProtocol], MappedIdentity]:
	
    result = source.adapter.finish(identity=identity, **response)
	# ensure_identity返回一个EI
    return cls.ensure_identity(
        source=source, result=result,
        allow_external=allow_external,
    )
```



##### 7. 微信登录

```python
路径：vac/facade/web/auth/challenge/wechat.py

@get('/api/login/wechat/session')
@api
def session_api():
    # 获取session_id
    session_id = request.query.get('session_id')
    validate_session_id(session_id)
	
    # 通过session_id获取用户实例
    if WechatSharedAdapter.instance.delegated:
        user = dog.wechat_session2user(session_id)
    else:
        content = REDIS_CONN.get(f"SESSION:wechat:{session_id}")
        # 如果没获取到则抛出异常
        if not content:
            raise FacadeException('SessionNotReady')
		# 如果已经扫码则抛出异常
        if content == b'SCANNED':
            raise FacadeException('QrcodeScanned')
		
		# 删除redis中的session_id
        REDIS_CONN.delete(f"SESSION:wechat:{session_id}")

        user = json.loads(content)
	
    # 将wx的openId作为unique_binding的key
    openid = user['openid']

    # 尝试恢复登录状态
    LoginState.resume()
    source = LoginState.assert_challenge(AdapterType.WECHAT_SHARED)

    # 通过openId 获取unique_binding中的数据
    binding = UniqueBindingRepository.find_binding(
        key=openid, name=KnownBindings.WECHAT_SHARED_OPENID,
    )
    if not binding:
        raise FacadeException('OpenIDNotBound')
	# 检测是否被锁定
    SecurityService.check_identity_locked(binding.identity_urn)
	
    identity = binding.load_identity()
    ChallengeManager.finish_challenge(
        source=source,
        identity=identity,
        result={
            'openid': openid,
            "user_agent": user['user_agent'],
            "remote_addr": user['remote_addr'],
            "request_id": user['request_id']
        },
        no_redirect=True,
    )

    return {
        'state': LoginState.pause(),
    }
```



#### 4.补充

##### 1. source的设计与分类

1.facade层
a.can_id：是否可以作为第⼀认证⽅式，可能会将identity检索出来提供给adapter层
**在代码vac/facade/web/auth/challenge下的多因子认证方式代码中，有一个bool类型的can_id字段，来判断是否该方式可以作为第一认证方式。一般在class类定义处**

b.challenge_type: LOCAL | EXTERNAL，本地认证优先，但可以指定外部认证⽅式
**在代码vac/facade/web/auth/challenge下的cas、wxwork代码中存在**

c.can(identity)：当前身份是否⽀持认证
**在代码vac/facade/web/auth/challenge下的多因子认证方式代码中，都有一个class类方法can来确认是否支持认证，返回bool类型**

d.enroll(...)：待设计

2.adapter层
a.require_identity：是否需要有现成的身份才能认证；如何为False，隐含了只能⽀持Account
b.identity_location: ACCOUNT / EXTERNAL 毫⽆意义，是否can_id，也就是，是否能产⽣EI/A 才是区别
**在代码vac/domain/directory/authn_method/下的文件中**

3.source层
a.register_account: 是否注册为Account，隐含了can_id=yes，否则没有创建EI的能⼒

```python
路径：vac/facade/web/auth/challenge/util.py

@classmethod
    def impl_cls(cls, typ: AdapterType):
        for sub in ServerSideRenderMethod.__subclasses__():
            if sub.__method__ == typ:
                return sub
            
@classmethod
def usable_sources(
        cls, identity: Optional[IdentityProtocol] = None,
        ignore_types: Container[AdapterType] = None,
        requirements: Requirements = None) -> list[Source]:
    # 从redis获取开启的sources
    enabled_sources = cls.enabled_sources()

    results = []
    for source in enabled_sources:
        # 对指定的来源进行跳过
        if ignore_types is not None and source.adapter_type in ignore_types:
            continue

        # 根据适配器的类型生成已经实现的cls
        impl_cls = cls.impl_cls(source.adapter_type)
        if impl_cls is None:
            continue
		
        # 如果身份存在则验证是否可以作为第一认证方式以及是否可以支持认证
        if identity:
            if not impl_cls.can(identity):
                continue
        elif not impl_cls.__can_id__:
            continue

        # 加入到results中
        results.append(source)

    
    if requirements:
        # 更新方法id和第二认证来源
        allowed_ids = set(requirements.method_ids or ())
        allowed_ids.update(requirements.second_factors or ())

        # 去重
        if allowed_ids:
            results = [
                source for source in results
                if source.id in allowed_ids
            ]

    return results
```



##### 2. make_binding

```python
@classmethod
    @transactional
    def make_binding(cls, identity_urn: str, name: str, key: str, override_identity=False,
                     source_id: int = CONSOLE_SOURCE_ID, source_urn: str = None,
                     reason: str = LinkReason.UserRequested) -> bool:
        """
        :param override_identity: override if name-key already bound to other identity
        :param source_id: as realm id
        :return: is overridden
        """
        if source_urn:
            source_id = Source.urn_id(source_urn) \
                if Source.urn_isinstance(source_urn) \
                else cls.CONSOLE_SOURCE_ID

        # 1. check name/key already bound to other identity
        # 检测key和名称的绑定
        existing: UniqueBinding = UniqueBindingRepository.find_binding(
            name=name, key=key, for_update=True,
        )

        deleted = False
        if existing:
            # 如果现有绑定的urn！=新的urn
            if existing.identity_urn != identity_urn:
                # 如果override_identity是否覆盖身份为否
                if not override_identity:
                    # 记录并返回异常
                    AuthnLogger.ignore_binding(
                        cause=reason,
                        reason=LinkReason.AlreadyBoundOtherIdentity,
                        name=name, key=key, conflicted='identity_urn',
                        current=existing.identity_urn,
                    )
                    raise DomainException('ConflictedBinding')

                # can only override matched source
				# 如果source_id不为控制台创建以及不等于现有的来源
                if source_id != cls.CONSOLE_SOURCE_ID and source_id != existing.source_id:
                    AuthnLogger.ignore_binding(
                        cause=reason,
                        reason=LinkReason.SourceNotMatch,
                        name=name, key=key, conflicted='identity_urn',
                        current=existing.identity_urn,
                    )
                    raise DomainException('BindingNotOwnedBySource')

                # delete redundant binding, which identity/name can also bound
                # 删除重复的绑定
                UniqueBindingRepository.delete(existing)
                deleted = True

                AuthnLogger.remove_binding(
                    reason=LinkReason.DropConflictedBinding,
                    binding=existing,
                )

        # 2. check identity/name is bound to other key
        # CONSOLE binding cannot be overridden
        # 检测身份与名称的绑定
        existing: UniqueBinding = UniqueBindingRepository.find_binding(
            name=name, identity_urn=identity_urn, for_update=True,
        )

        # 如果存在则返回删除
        
        if existing:
            if existing.key == key:
                return deleted

            # can only override matched source
            if source_id != cls.CONSOLE_SOURCE_ID and source_id != existing.source_id:
                AuthnLogger.ignore_binding(
                    cause=reason,
                    reason=LinkReason.SourceNotMatch,
                    name=name, key=key, conflicted='key',
                    current=existing.key,
                )
                raise DomainException('BindingNotOwnedBySource')

            old_key, existing.key = existing.key, key
            UniqueBindingRepository.merge(existing)

            AuthnLogger.change_binding_key(
                reason=reason, binding=existing, old_key=old_key,
            )
            return True
        else:
            # 添加绑定
            binding = UniqueBinding(
                name=name, key=key,
                identity_urn=identity_urn, source_id=source_id,
            )
            UniqueBindingRepository.add(binding)

            AuthnLogger.make_binding(
                reason=reason, binding=binding,
            )

            return deleted
```

##### 3. challenge

```python
路径：vac/facade/web/auth/challenge/manager.py



class ChallengeManager:
    @classmethod
    def initiate_challenge(cls, challenge: ChallengeContext):
        # real impl
        impl = ChallengeUtil.impl_cls(challenge.selected.adapter_type)

        LoginState.identity_urn = challenge.identity.urn() if challenge.identity else None
        LoginState.current_challenge = challenge
        LoginState.mark_modified()
        # 调用实现的initiate_challenge
        return impl.initiate_challenge(source=challenge.selected, identity=challenge.identity)

    @classmethod
    # 针对位置用户进行身份识别
    def start_identify_challenge(cls, requirements: Requirements):
        # unknown user
        # 获取一个可认证的身份列表，传入需求类，需要特定的来源
        usable_sources = ChallengeUtil.usable_sources(requirements=requirements)
        if not usable_sources:
            raise FacadeException('NoUsableMethodAvailable')

        return cls.initiate_challenge(ChallengeContext(
            selected=usable_sources[0],
            alternatives=usable_sources,
        ))

    @classmethod
    def start_challenge(cls, identity: IdentityProtocol,
                        preferred: list[list[int, str]], local_first: bool = True,
                        requirements: dict = None):
        if isinstance(identity, Account) and identity.status is AccountStatus.RESET_REQUIRED:
            # TODO: handle reset_required
            ...
		# 获取可用的来源
        usable_sources = ChallengeUtil.usable_sources(identity, requirements=requirements)
        if not usable_sources:
            raise FacadeException('NoUsableMethodAvailable')
		
        # 启动实现的方法
        return cls.initiate_challenge(ChallengeContext(
            identity=identity,
            selected=ChallengeUtil.select_source(
                sources=usable_sources, preferred=preferred,
                local_first=local_first,
            ),
            alternatives=usable_sources,
        ))

    @classmethod
    def start_alternative_challenge(cls, identity: IdentityProtocol,
                                    selected: Source, requirements: Requirements = None):
        usable_sources = ChallengeUtil.usable_sources(identity, requirements=requirements)
        if not usable_sources:
            raise FacadeException('NoUsableMethodAvailable')

        return cls.initiate_challenge(ChallengeContext(
            identity=identity,
            selected=selected,
            alternatives=usable_sources,
        ))

    @classmethod
    def finish_challenge(
            cls, source: Source, identity: IdentityProtocol,
            result: Any = None, no_redirect=False, is_combined: bool = False):
        # 如果当前登录态的挑战id！=来源id或者未合并 则重启登录状态
        if not is_combined and LoginState.current_challenge_id != source.id:
            print('ChallengeContextMismatch')
            return LoginState.restart()

        # 如果登录的身份urn存在并且正在挑战
        if LoginState.identity_urn and LoginState.challenges:
            if LoginState.identity_urn != identity.urn():
                print('ChallengeContextMismatch')
                return LoginState.restart()
        else:
            # 身份来源赋值
            LoginState.identity_urn = identity.urn()

        AuditService.record_authn(
            session_id=LoginState.session_id,
            source=source,
            identity=identity,
            result=result,
        )

        # 标记更改
        LoginState.mark_modified()
		# 清空挑战
        LoginState.clear_challenge()
        # 添加结果
        LoginState.append_challenge_result(
            source=source, identity=identity, result=result,
        )

        # 如果no_redirect为false则重定向到登录
        if not no_redirect:
            LoginState.pause_redirect('/api/login')

    @classmethod
    def continue_challenge(cls, identity: IdentityProtocol, completed: list[ChallengeResult],
                           selected: Source = None, requirements: Requirements = None):
        from vac.facade.web.auth.challenge.mfa import AuthnMFA
        # 如果有多因子则继续开启
        if challenge := AuthnMFA.next_challenge(
                identity=identity, completed=completed,
                selected=selected, requirements=requirements):

            return cls.initiate_challenge(challenge)
		# 检测允许IP
        from vac.facade.web.auth.challenge.allowed_ip import IPWhitelistCheck
        if challenge := IPWhitelistCheck.next_challenge(
                identity=identity, completed=completed):
            return cls.initiate_challenge(challenge)

        # 导入模块
        from vac.facade.web.auth.challenge.confirmation import VerifyConfirmation
        if challenge := VerifyConfirmation.next_challenge(
                identity=identity, completed=completed):

            return cls.initiate_challenge(challenge)

        # 等待登录模块
        from vac.facade.web.auth.challenge.await_login_approval import AwaitLoginApproval
        if challenge := AwaitLoginApproval.next_challenge(
                identity=identity, completed=completed):

            return cls.initiate_challenge(challenge)
		
        # account状态
        from vac.facade.web.auth.challenge.staus import AccountStatusCheck
        if challenge := AccountStatusCheck.next_challenge(
                identity=identity, completed=completed):

            return cls.initiate_challenge(challenge)
		
        # 强制修改密码
        from vac.facade.web.auth.challenge.change_password import ForceChangePassword
        if challenge := ForceChangePassword.next_challenge(
                identity=identity, completed=completed):

            return cls.initiate_challenge(challenge)

        challenges = {
            'challenges': [{
                'id': result.source_id,
                'type': result.method.name,
                'at': result.at,
            } for result in LoginState.challenges]
        }

        AuditService.record_issue_session(
            session_id=LoginState.session_id,
            identity=identity,
            result=challenges,
        )

        AuditService.notify_user_login(
            identity=identity,
            result=challenges,
        )

        login_identity(
            identity=identity,
            session_id=LoginState.session_id,
            challenges=[{
                'id': result.source_id,
                'type': result.method.name,
                'at': result.at,
            } for result in completed],
        )

        # SOTER集成在了FIDO2_PLATFORM里, 因此这需要转一下
        platform_source = SourceRepository.list_by_types([AdapterType.FIDO2_PLATFORM])[0]
        sources = [
            [platform_source.id if result.method == AdapterType.SOTER else result.source_id,
             AdapterType.FIDO2_PLATFORM.name if result.method == AdapterType.SOTER else result.method.name]
            for result in completed
        ]
        record_last_login(
            identity_urn=identity.urn(),
            sources=sources,
            nickname=identity.display_name,
            avatar_url=identity['avatar_url'],
        )

        return LoginState.restart()
```
