#### 1

##### 修改目的

- os.Exit(1)是终止程序，return是返回错误，return更灵活，更常见。

##### 主要修改内容

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-34-25-image.png)**修改后**:

```go
if *execlPath == "" {
    return fmt.Errorf("你必须指定一个execl文件的路径")
}
```

#### 2

##### 修改目的

- 打开文件、数据库连接等要及时close，不对文件句柄进行关闭，会造成资源泄露、性能问题、或者有可能导致文件损坏的情况。

##### 主要修改内容

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-34-35-image.png)

**修改后**:

```go
execlFile, err := xlsx.OpenFile(*execlPath)
defer f.Close()
```

#### 3

##### 修改目的

- 该场景为从excel读取数据赋值到结构体，需要对string类型的数据进行去除旁边空格操作，否则后面进行数据比对，数据操作时可能会出现差错。

##### 主要修改内容

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-34-45-image.png)

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

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-35-03-image.png)

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

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-35-13-image.png)

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

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-35-22-image.png)

**修改后**:

```go
loginNames := make(map[string]*Student)
```

#### 7

##### 修改目的

- 重复的可抽离的代码可以拿出来，更清晰

##### 主要修改内容

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-35-35-image.png)

**修改后**:

```go
const objectFmt = "冲突对象: [学号: %s，姓名: %s，性别: %s，状态: %s，手机号: %s，行数: %d]，冲突原因：%s，操作结果：%s \n""\

fmt.Sprintf(objectFmt,....)
```

#### 8

##### 修改目的

- 该方法的作用是处理业务，不应该放到util包中，而是应该放到service中或者main下

##### 主要修改内容

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-35-55-image.png)

修改后**:

```go
新建service包，将该方法放入service包下
```

#### 9

##### 修改目的

- 判断手机号是否为空时写错位置

##### 主要修改内容

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-17-01-image.png)

#### 10

##### 修改目的

- 写入文件是io操作，应该把数据聚集起来，少次多量写入。

##### 主要修改内容

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-21-13-image.png)**修改后**:

```go
将line封装成了一个多行的数据[][]map
```

#### 11

##### 修改目的

- 场景为启动协程同时写excel和mysql，有mysql写入错误，但是excel写入的数据出现问题的情况。

##### 主要修改内容

**修改前**:**![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-23-31-image.png)修改后**:

```go
将协程去掉了，顺序是先写excel表，再写mysql
```

#### 12

##### 修改目的

- 方法，变量命名应该遵循统一规则例如驼峰命名；ProcessStudent函数应该返回少量变量，尽量合并到一起。

##### 主要修改内容

**修改前**:**![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-25-14-image.png)修改后**:

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

**修改前**:**![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-28-23-image.png)修改后**:

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

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-30-28-image.png)**修改后**:

```go
删掉改方法，在主函数执行，map的初始化
```

#### 15

##### 修改目的

- 该方法初始化四个map，放入到主函数执行，不如直接在主函数初始化

##### 主要修改内容

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-18-32-31-image.png)**修改后**:

```go
删掉改方法，在主函数执行，map的初始化
```

#### 16

##### 修改目的

- 给结构体赋值时，默认为空的字段，不需要写。

##### 主要修改内容

**修改前**:**![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-19-21-24-image.png)修改后**:

```go
删掉默认为nil的字段
```

#### 17

##### 修改目的

- 逻辑上重复了，新建status、reason、result字段，放到后面判断，然后再统一写入

##### 主要修改内容

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-19-22-45-image.png)**修改后**:

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

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-19-24-43-image.png)**修改后**:

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

**修改前**:**![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-19-27-14-image.png)修改后**:

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

**修改前**:**![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-19-29-00-image.png)修改后**:

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

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-19-31-52-image.png)**修改后**:

```go
log记录使用logrus库
```

#### 22

##### 修改目的

- db不需要暴露出去，小写就可以；不使用全局err

##### 主要修改内容

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-19-32-33-image.png)**修改后**:

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

**修改前**:![](C:\Users\johnxu\AppData\Roaming\marktext\images\2024-10-15-19-34-06-image.png)**修改后**:

```go
// CreateAccount 基础函数,插入account表
func CreateAccount(account *Account, tx *gorm.DB) error {
	return tx.Create(&account).Error
}
```
