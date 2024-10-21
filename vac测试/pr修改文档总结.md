#### 1

##### 修改目的

- os.Exit(1)是终止程序，return是返回错误，return更灵活，更常见。

##### 主要修改内容

**修改前**:![](assets\2024-10-15-18-34-25-image.png)**修改后**:

```go
if *execlPath == "" {
    return fmt.Errorf("你必须指定一个execl文件的路径")
}
```

#### 2

##### 修改目的

- 打开文件、数据库连接等要及时close，不对文件句柄进行关闭，会造成资源泄露、性能问题、或者有可能导致文件损坏的情况。

##### 主要修改内容

**修改前**:![](assets\2024-10-15-18-34-35-image.png)

**修改后**:

```go
execlFile, err := xlsx.OpenFile(*execlPath)
defer f.Close()
```

#### 3

##### 修改目的

- 该场景为从excel读取数据赋值到结构体，需要对string类型的数据进行去除旁边空格操作，否则后面进行数据比对，数据操作时可能会出现差错。

##### 主要修改内容

**修改前**:![](assets\2024-10-15-18-34-45-image.png)

**修改后**:

```go
student := util.Student{
                ID:       strings.TrimSpace(row.Cells[0].String()),
                .
                .
                .
}
```

#### 4

##### 修改目的

- 函数名NewMysql方法代表着新建一个Mysql引擎，可能会多次使用，与现有逻辑不符；InitMysql代表初始化mysql引擎，对现有DB进行初始化。
- 初始化Mysql会产生错误，而且不属于顶层方法，应该返回一个error，上层函数判断错误。

##### 主要修改内容

**修改前**:![](assets\2024-10-15-18-35-03-image.png)

**修改后**:

```go
func InitMysql(dsn string) error {
    var err error
    db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
    if err != nil {
        logrus.Error("连接数据库失败: %v\n", err)
        return err
    }
    return nil
}
```

#### 5

##### 修改目的

- 代码中的常量统一都提到最前面

##### 主要修改内容

**修改前**:![](assets\2024-10-15-18-35-13-image.png)

**修改后**:

```go
const (
    phoneRegexpRule = `^1[3-9]\d{9}$`
)

var phoneRegexp = regexp.MustCompile(phoneRegexpRule)

func IsInValidPhone(phone string) bool {
    return !phoneRegexp.MatchString(phone)
}
```

#### 6

##### 修改目的

- 代码中被引用多次的结构体用指针，减小开销

##### 主要修改内容

**修改前**:![](assets\2024-10-15-18-35-22-image.png)

**修改后**:

```go
loginNames := make(map[string]*Student)
```

#### 7

##### 修改目的

- 重复的可抽离的代码可以拿出来，更清晰

##### 主要修改内容

**修改前**:![](assets\2024-10-15-18-35-35-image.png)

**修改后**:

```go
const objectFmt = "冲突对象: [学号: %s，姓名: %s，性别: %s，状态: %s，手机号: %s，行数: %d]，冲突原因：%s，操作结果：%s \n""\

fmt.Sprintf(objectFmt,....)
```

#### 8

##### 修改目的

- 该方法的作用是处理业务，不应该放到util包中，而是应该放到service中或者main下

##### 主要修改内容

**修改前**:![](assets\2024-10-15-18-35-55-image.png)

修改后**:

```go
新建service包，将该方法放入service包下
```

#### 9

##### 修改目的

- 判断手机号是否为空时写错位置

##### 主要修改内容

**修改前**:![](assets\2024-10-15-18-17-01-image.png)

#### 10

##### 修改目的

- 写入文件是io操作，应该把数据聚集起来，少次多量写入。

##### 主要修改内容

**修改前**:![](assets\2024-10-15-18-21-13-image.png)**修改后**:

```go
将line封装成了一个多行的数据[][]map
```

#### 11

##### 修改目的

- 场景为启动协程同时写excel和mysql，有mysql写入错误，但是excel写入的数据出现问题的情况。

##### 主要修改内容

**修改前**:**![](assets\2024-10-15-18-23-31-image.png)修改后**:

```go
将协程去掉了，顺序是先写excel表，再写mysql
```

#### 12

##### 修改目的

- 方法，变量命名应该遵循统一规则例如驼峰命名；ProcessStudent函数应该返回少量变量，尽量合并到一起。

##### 主要修改内容

**修改前**:**![](assets\2024-10-15-18-25-14-image.png)修改后**:

```go
repeatList 使用驼峰命名，ProcessStudent方法返回一个存在错误的结构体：
type AccountProcessingResult struct {
    IDMap           map[string][]map[string]string
    PhoneMap        map[string][]map[string]string
    InValidPhoneMap []map[string]string
    InValidNameMap  []map[string]string
    insertErr       []map[string]string
}
```

#### 13

##### 修改目的

- 加入binding时需要看mobile的值是否为空，把判断部分拿出来，就不需要进入addBinding方法中，减少消耗。

##### 主要修改内容

**修改前**:**![](assets\2024-10-15-18-28-23-image.png)修改后**:

```go
addBinding := func(name, key string, accID int) {
        if key != "" {
    // 逻辑
}
```

#### 14

##### 修改目的

- 该方法初始化四个map，放入到主函数执行，不如直接在主函数初始化

##### 主要修改内容

**修改前**:![](assets\2024-10-15-18-30-28-image.png)**修改后**:

```go
删掉改方法，在主函数执行，map的初始化
```

#### 15

##### 修改目的

- 该方法初始化四个map，放入到主函数执行，不如直接在主函数初始化

##### 主要修改内容

**修改前**:![](assets\2024-10-15-18-32-31-image.png)**修改后**:

```go
删掉改方法，在主函数执行，map的初始化
```

#### 16

##### 修改目的

- 给结构体赋值时，默认为空的字段，不需要写。

##### 主要修改内容

**修改前**:**![](assets\2024-10-15-19-21-24-image.png)修改后**:

```go
删掉默认为nil的字段
```

#### 17

##### 修改目的

- 逻辑上重复了，新建status、reason、result字段，放到后面判断，然后再统一写入

##### 主要修改内容

**修改前**:![](assets\2024-10-15-19-22-45-image.png)**修改后**:

```go
var status, reason, result string

            switch errType {
            case 1:
                if student["data_source"] == "mysql" {
                    continue
                }
                reason = "学号冲突"
                if index == 0 {
                    status = "正常"
                    result = "已入库"
                } else {
                    status = "异常"
                    result = "未入库"
                }
            case 2:
                if student["data_source"] == "mysql" {
                    continue
                }
                reason = "手机号冲突"
                if index == 0 {
                    status = "正常"
                    result = "已入库"
                } else {
                    status = "异常"
                    result = "手机号置空后入库"
                }
            case 3:
                status = "异常"
                reason = "手机号格式不符"
                result = "手机号置空后入库"
            case 4:
                status = "异常"
                reason = "姓名长度过长"
                result = "截取后入库"
            }

            // 在循环结束后统一设置值
            f.SetCellValue(sheetName, fmt.Sprintf("B%d", startRow), status)
            f.SetCellValue(sheetName, fmt.Sprintf("H%d", startRow), reason)
            f.SetCellValue(sheetName, fmt.Sprintf("I%d", startRow), result)
```

#### 18

##### 修改目的

- 字符串拼接不要使用 +，耗费资源相对大

##### 主要修改内容

**修改前**:![](assets\2024-10-15-19-24-43-image.png)**修改后**:

```go
// 将字符串拼接落到Account中，然后IdentityURN直接传入account.IdentityURN
func (a *Account) IdentityURN() string {
    return fmt.Sprintf("urn:account/%s", strconv.Itoa(a.ID))
}
```

#### 19

##### 修改目的

- 从excel读取数据时改用map，可只存储想要的字段。

##### 主要修改内容

**修改前**:**![](assets\2024-10-15-19-27-14-image.png)修改后**:

```go
// 使用[]map[string]string来接受数据
var students []map[string]string

    for _, sheet := range excelFile.Sheets {
        for i, row := range sheet.Rows {
            if len(row.Cells) < 5 || i == 0 {
                continue
            }
            students = append(students, map[string]string{
                "login_name":  strings.TrimSpace(row.Cells[0].String()),
                "full_name":   strings.TrimSpace(row.Cells[1].String()),
                "gender":      strings.TrimSpace(row.Cells[2].String()),
                "status":      strings.TrimSpace(row.Cells[3].String()),
                "mobile":      strings.TrimSpace(row.Cells[4].String()),
                "row_number":  strconv.Itoa(i + 1),
                "data_source": DATASOURCE_EXCEL,
            })
        }
    }
```

#### 20

##### 修改目的

- 基础函数不可以batch批量插入

##### 主要修改内容

**修改前**:**![](assets\2024-10-15-19-29-00-image.png)修改后**:

```go
// CreateAccount 基础函数,插入account表
func CreateAccount(account *Account, tx *gorm.DB) error {
    return tx.Create(&account).Error
}
// CreateBinding 基础函数,插入unique_binding表
func CreateBinding(binding *UniqueBinding, tx *gorm.DB) error {
    return tx.Create(&binding).Error
}
```

#### 21

##### 修改目的

- 基础函数不可以batch批量插入

##### 主要修改内容

**修改前**:![](assets\2024-10-15-19-31-52-image.png)**修改后**:

```go
log记录使用logrus库
```

#### 22

##### 修改目的

- db不需要暴露出去，小写就可以；不使用全局err

##### 主要修改内容

**修改前**:![](assets\2024-10-15-19-32-33-image.png)**修改后**:

```go
var db *gorm.DB

func InitMysql(dsn string) error {
    var err error
    db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
    if err != nil {
        logrus.Error("连接数据库失败: %v\n", err)
        return err
    }
    return nil
}
```

#### 23

##### 修改目的

- 函数命名不符合函数的作用，而且批量写入数据库，不需要返回[]*Account,使用1account对应2unique_binding最小单元

##### 主要修改内容

**修改前**:![](assets\2024-10-15-19-34-06-image.png)**修改后**:

```go
// CreateAccount 基础函数,插入account表
func CreateAccount(account *Account, tx *gorm.DB) error {
    return tx.Create(&account).Error
}
```

#### 24

##### 修改目的

- util.GenerateRandomString()方法的作用是生成unique_id,变量名与实际用途不符。

##### 主要修改内容

**修改前**:![](assets\2024-10-16-15-03-05-image.png)**修改后**:

```go
uniqueId := util.GenerateRandomString()
```

#### 25

##### 修改目的

- 常量提出来

##### 主要修改内容

**修改前**:![](assets\2024-10-16-15-04-42-image.png)**修改后**:

```go
const (
    ACCOUNT_SOURCEURN   = "CONSOLE"
    ACCOUNT_STATUS      = "CONFIRMED"
)
....

	return &Account{
		LoginName:      accountMap["login_name"],
		Mobile:         accountMap["mobile"],
		FullName:       accountMap["full_name"],
		MobileVerified: mobileVerified,
		UniqueID:       accountMap["unique_id"],
		Attributes:     string(marshal),
		SourceURN:      ACCOUNT_SOURCEURN,
		Status:         ACCOUNT_STATUS,
	}
```

#### 26

##### 修改目的

- 该方法是从excel读取数据赋值到map中，因读取的数据key都为string类型，没必要使用map[string]interface{},反而解析时需要使用.(string)进行断言，浪费资源。

##### 主要修改内容

**修改前**:**![](assets\2024-10-16-15-07-24-image.png)修改后**:

```go
var students []map[string]string

	for _, sheet := range excelFile.Sheets {
		for i, row := range sheet.Rows {
			if len(row.Cells) < 5 || i == 0 {
				continue
			}
			students = append(students, map[string]string{
				"login_name":  strings.TrimSpace(row.Cells[0].String()),
				"full_name":   strings.TrimSpace(row.Cells[1].String()),
				"gender":      strings.TrimSpace(row.Cells[2].String()),
				"status":      strings.TrimSpace(row.Cells[3].String()),
				"mobile":      strings.TrimSpace(row.Cells[4].String()),
				"row_number":  strconv.Itoa(i + 1),
				"data_source": DATASOURCE_EXCEL,
			})
		}
	}
```

#### 27

##### 修改目的

- 该方法是从excel读取数据，对数据处理后，返回产生冲突的map。一个函数做了两件业务，使得方法作用不明确。

##### 主要修改内容

**修改前**:![](assets\2024-10-16-15-10-04-image.png)**修改后**:

```go

// 修改成两个方法，
// ReadExcelData 读取excel文件内容写入到map
// ProcessStudentsData 处理ReadExcelData生成的map信息生成冲突map


// ReadExcelData 读取excel文件内容写入到map
func ReadExcelData(excelPath string) ([]map[string]string, error) {
	excelFile, err := xlsx.OpenFile(excelPath)
	if err != nil {
		logrus.Error("打开excel文件错误: %v\n", err)
		return nil, err
	}

	var students []map[string]string

	for _, sheet := range excelFile.Sheets {
		for i, row := range sheet.Rows {
			if len(row.Cells) < 5 || i == 0 {
				continue
			}
			students = append(students, map[string]string{
				"login_name":  strings.TrimSpace(row.Cells[0].String()),
				"full_name":   strings.TrimSpace(row.Cells[1].String()),
				"gender":      strings.TrimSpace(row.Cells[2].String()),
				"status":      strings.TrimSpace(row.Cells[3].String()),
				"mobile":      strings.TrimSpace(row.Cells[4].String()),
				"row_number":  strconv.Itoa(i + 1),
				"data_source": DATASOURCE_EXCEL,
			})
		}
	}

	return students, nil
}

// ProcessStudentsData 处理excel信息生成map
func ProcessStudentsData(students []map[string]string) ([]map[string]string, *AccountProcessingResult, error) {
	// 初始化 AccountProcessingResult 结构体
	studentMaps := &AccountProcessingResult{
		IDMap:           make(map[string][]map[string]string),
		PhoneMap:        make(map[string][]map[string]string),
		InValidPhoneMap: make([]map[string]string, 0),
		InValidNameMap:  make([]map[string]string, 0),
	}
	var accountMap []map[string]string

	// 初始化唯一标识
	studentsSet := make(map[string]map[string]string)   // 进行学号去重操作
	phoneExistMap := make(map[string]map[string]string) // 进行手机号去重操作
	uniqueIdMap := make(map[string]struct{})

	// 获取账户列表
	accountList, err := entity.GetAccountList()
	if err != nil {
		return accountMap, studentMaps, err // 返回 studentMaps
	}

	// 填充学生信息
	for _, account := range accountList {
		stu := map[string]string{
			"login_name":  account.LoginName,
			"mobile":      account.Mobile,
			"full_name":   account.FullName,
			"data_source": DATASOURCE_MYSQL,
		}
		studentsSet[account.LoginName] = stu

		if account.Mobile != "" {
			phoneExistMap[account.Mobile] = stu
		}
		uniqueIdMap[account.UniqueID] = struct{}{}
	}

	for _, student := range students {
		uniqueId := util.GenerateRandomString()

		// 检查是否生成了重复的 uniqueId
		if _, exists := uniqueIdMap[uniqueId]; exists {
			logrus.Error("生成了重复的 unique_id")
			return accountMap, studentMaps, errors.New("生成了重复的 unique_id") // 返回 studentMaps
		}

		// 生成账户
		account := map[string]string{
			"login_name":     student["login_name"],
			"mobile":         student["mobile"],
			"full_name":      student["full_name"],
			"student_status": student["status"],
			"gender":         student["gender"],
			"unique_id":      uniqueId,
		}

		// 学号重复处理
		if existingStudent, exist := studentsSet[student["login_name"]]; exist {
			if _, idExist := studentMaps.IDMap[student["login_name"]]; !idExist {
				studentMaps.IDMap[student["login_name"]] = []map[string]string{existingStudent}
			}
			studentMaps.IDMap[student["login_name"]] = append(studentMaps.IDMap[student["login_name"]], student)
			continue
		} else {
			studentsSet[student["login_name"]] = student
		}

		// 手机号重复处理
		if existingPhoneStudent, e := phoneExistMap[student["mobile"]]; e {
			account["mobile"] = ""
			if _, exists := studentMaps.PhoneMap[student["mobile"]]; !exists {
				studentMaps.PhoneMap[student["mobile"]] = []map[string]string{existingPhoneStudent}
			}
			studentMaps.PhoneMap[student["mobile"]] = append(studentMaps.PhoneMap[student["mobile"]], student)
		} else {
			phoneExistMap[student["mobile"]] = student
		}

		// 手机号不合法处理
		if student["mobile"] != "" && util.IsInValidPhone(student["mobile"]) {
			account["mobile"] = ""
			studentMaps.InValidPhoneMap = append(studentMaps.InValidPhoneMap, student)
		}

		// 姓名不合法处理
		if util.IsInValidName(student["full_name"]) {
			account["full_name"] = util.InterceptName(student["full_name"])
			studentMaps.InValidNameMap = append(studentMaps.InValidNameMap, student)
		}

		// 添加到账户列表
		accountMap = append(accountMap, account)
	}

	return accountMap, studentMaps, nil // 确保返回 studentMaps
}


```

#### 28

##### 修改目的

- WriteStudentsToExcel方法和AppendStudentsToExcel一个是创建新的excel文件并写入，一个是追加到已有的excel并写入，这两个方法有很多地方时重复的，所以使用一个变量来控制使用该方法时是写入还是追加。

##### 主要修改内容

**修改前**:![](assets\2024-10-16-15-14-35-image.png)**修改后**:

```go
// WriteOrAppendStudentsToExcel 写入excel文件 根据appendData决定是追加到excel还是创建新的excel
func WriteOrAppendStudentsToExcel(studentMaps *AccountProcessingResult, filePath string, appendData bool) error {
	var f *excelize.File
	var err error

	if appendData {
		// 打开现有文件
		f, err = excelize.OpenFile(filePath)
		if err != nil {
			return err
		}
	} else {
		// 创建新的 Excel 文件
		f = excelize.NewFile()
	}
	defer f.Close()

	sheetName := "学生导入冲突情况"
	index, err := f.NewSheet(sheetName)
	if err != nil && !appendData {
		return err
	}

	if !appendData {
		headers := []string{"行号", "状态", "学号", "姓名", "性别", "状态", "电话", "冲突原因", "处理结果"}
		for col, header := range headers {
			cell := fmt.Sprintf("%s%d", string(rune('A'+col)), 1)
			f.SetCellValue(sheetName, cell, header)
		}
	}

	// 获取当前行数以便追加
	var row int
	if appendData {
		rows, err := f.GetRows(sheetName)
		if err != nil {
			return err
		}
		row = len(rows) + 1 // 追加数据时，从最后一行开始
	} else {
		row = 2 // 覆盖时，从第二行开始
	}

	mapToSlice := func(in map[string][]map[string]string) (out [][]map[string]string) {
		for _, i := range in {
			out = append(out, i)
		}
		return
	}

	// 填充学生数据
	row = toSheet(f, sheetName, mapToSlice(studentMaps.IDMap), row, 1)                      // errType 1代表学号冲突
	row = toSheet(f, sheetName, mapToSlice(studentMaps.PhoneMap), row, 2)                   // errType 2代表手机号冲突
	row = toSheet(f, sheetName, [][]map[string]string{studentMaps.InValidPhoneMap}, row, 3) // errType 3代表手机号非法格式
	row = toSheet(f, sheetName, [][]map[string]string{studentMaps.InValidNameMap}, row, 4)  // errType 4代表姓名过长
	row = toSheet(f, sheetName, [][]map[string]string{studentMaps.insertErr}, row, 4)       // errType 4代表姓名过长

	// 设置当前工作表并保存文件
	f.SetActiveSheet(index)
	if err = f.SaveAs(filePath); err != nil {
		return err
	}

	return nil
}
```

#### 29

##### 修改目的

- 在外部有一个for range循环，遍历accounts，单个实体就是accountItem，使用dataMapWithLoginName, err := entity.GenerateAccountDataMap(account)的目的就是获取一个account，多此一举，不如直接用accountItem。

##### 主要修改内容

**修改前**:![](assets\2024-10-16-15-20-26-image.png)**修改后**:

```go


```

#### 30

##### 修改目的

- 若函数返回error，则使用log记录时，需要用logrus.Error

##### 主要修改内容

**修改前**:*![](assets\2024-10-16-15-23-55-image.png)



#### 31

##### 修改目的

- 此处是数据入库代码，一个account对应两个unique_binding,进行入库，但是我们需要防止在程序运行时，有其他方法插入数据库，导致导入脚本中的数据没插入数据库但是冲突情况excel没展示的情况，所以根据unique_binding的索引来判断，需要保留result的结果进行判断。
- 在函数中使用了gorm的db.Transaction(func(tx *gorm.DB) error {}),再该方法里自动启动事务操作，若返回错误，则自动rollback。

##### 主要修改内容

**修改前**:![](assets\2024-10-16-15-25-14-image.png)**修改后**:

```go
// CreateAccountWithBinding account和unique_binding写入数据库 1对2的关系
// 返回值的int 1代表学号冲突 2代表手机号冲突
func CreateAccountWithBinding(account *Account) (int, error) {
	var result int

	// 事务会自动启动以及提交
	err := db.Transaction(func(tx *gorm.DB) error {
		err := CreateAccount(account, tx)
		if err != nil {
			logrus.Error("生成account错误:%v\n", err)
			return err
		}

		// 如果在运行该程序时，有人对数据库进行写操作，导致loginName或Mobile重复的情况
		bindingWithLoginName := GenerateBinding(BINDING_LOGIN_NAME, account.LoginName, account.IdentityURN())
		err = CreateBinding(bindingWithLoginName, tx)
		if err != nil {
			if strings.Contains(err.Error(), "1062") && strings.Contains(err.Error(), "uni_name_key") {
				result = 1
			}

			logrus.Error("创建name_binding失败:%v\n", err)
			return err
		}

		if account.Mobile != "" {
			bindingWithMobile := GenerateBinding(BINDING_MOBILE_NAME, account.Mobile, account.IdentityURN())
			err = CreateBinding(bindingWithMobile, tx)
			if err != nil {
				// 1062是mysql错误代码 表示唯一索引重复
				if strings.Contains(err.Error(), "1062") && strings.Contains(err.Error(), "uni_name_key") {
					// account 的手机号置空
					err = ClearAccountMobile(account.ID, tx)
					if err != nil {
						logrus.Error("account手机号置空失败:%v\n", err)
						return err
					}
					result = 2
				} else {
					logrus.Error("创建mobile_binding失败:%v\n", err)
					return err
				}
			}
		}

		return nil
	})

	if result != 0 {
		return result, nil
	}

	return result, err
}

```

#### 32

##### 修改目的

- 数据库中mobile和mobile_verfied是一个整体，要么都有，要么都没有。

##### 主要修改内容

**修改前**![](assets\2024-10-16-15-30-55-image.png)**修改后**:

```go
if account.Mobile != "" {
			bindingWithMobile := GenerateBinding(BINDING_MOBILE_NAME, account.Mobile, account.IdentityURN())
			err = CreateBinding(bindingWithMobile, tx)
			if err != nil {
				// 1062是mysql错误代码 表示唯一索引重复
				if strings.Contains(err.Error(), "1062") && strings.Contains(err.Error(), "uni_name_key") {
					// account 的手机号置空
					err = ClearAccountMobile(account.ID, tx)
					if err != nil {
						logrus.Error("account手机号置空失败:%v\n", err)
						return err
					}
					result = 2
				} else {
					logrus.Error("创建mobile_binding失败:%v\n", err)
					return err
				}
			}
```
