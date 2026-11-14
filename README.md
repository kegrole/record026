# jwtverify

只依赖 Python 标准库的 JWT（HMAC）校验工具。面对恶意构造的令牌，
判定结论稳定：所有解码失败都以错误值返回，绝不抛出异常；
签名比较走常量时间比较；`kid` 绝不参与文件路径拼接。

## 运行

```bash
python -m jwtverify.cli --tokens demo/tokens.txt --keys demo/keys.json --out out/report.json
```

命令结束后在 stdout 打印一行摘要（令牌总数、有效数、拒绝数、按 reason
分类的分布），完整 JSON 报告写入 `--out` 指定的文件。

测试：

```bash
cd tests && python -m unittest test_jwtverify -v
# 或在仓库根目录：python -m unittest discover -s tests -v
```

## 判定规则

### 算法白名单

- 只接受 `HS256` 与 `HS384`。
- `alg=none` 直接拒绝（`alg_none`）；header 缺少 `alg` 直接拒绝（`alg_missing`）；
  其他算法（如 `RS256`）一律拒绝（`alg_not_allowed`）。
- 拒绝算法混淆：按 header 声明的算法重算签名不匹配、但按另一种白名单
  算法能匹配时，判 `alg_mismatch`；任何白名单算法都匹配不上才判
  `bad_signature`。
- 签名比较使用 `hmac.compare_digest` 常量时间比较。

### 时效容差

时钟容差固定为 **30 秒**（`jwtverify.validator.CLOCK_TOLERANCE`）：

- `exp < now - 30` 判 `expired`；落在容差范围内或仍在未来均判有效。
- `nbf > now + 30` 判 `not_yet_valid`。

### kid 处理约定

- `kid` 只允许命中密钥表（`keys.json` 的 `keys` 对象）里的键。
- 含 `/`、`\\` 或 `..` 的 `kid` 直接拒绝（`bad_kid`）。
- `kid` 仅作为字典键查表，绝不拼接文件路径、不触发任何文件读取。

### iss / aud

- `iss` 必须等于密钥配置里的 `issuer`，否则判 `bad_iss`。
- `aud` 可以是字符串或字符串数组；数组（或单值）里必须包含配置里的
  `audience`，否则判 `bad_aud`，并在 `detail` 中写明期望的受众标识。

## 密钥配置（demo/keys.json）

```json
{
  "issuer": "demo-issuer",
  "audience": "demo-client",
  "keys": {"demo-key-1": "..."}
}
```

## 报告字段

每条令牌一个记录：

| 字段 | 含义 |
| --- | --- |
| `token_id` | 按输入顺序生成的编号（`token-001` …） |
| `valid` | 是否通过全部校验 |
| `reason` | 拒绝原因；当且仅当 `valid` 为 `true` 时为空串 `""` |
| `detail` | 可选，补充信息（如期望的 iss/aud、算法混淆详情） |
| `claims` | 标准声明摘要（exp、nbf、iat、iss、aud、sub） |

报告中绝不出现令牌原文与密钥明文。

### reason 取值表

| reason | 含义 |
| --- | --- |
| `""` | 校验通过（仅 `valid=true`） |
| `malformed` | 三段结构、base64url 或 JSON 解析失败 |
| `alg_missing` | header 缺少 `alg` |
| `alg_none` | `alg=none` |
| `alg_not_allowed` | `alg` 不在白名单（如 RS256） |
| `bad_kid` | `kid` 缺失、含路径字符或未命中密钥表 |
| `bad_signature` | HMAC 签名校验失败 |
| `alg_mismatch` | header 声明的算法与实际签名算法不一致 |
| `invalid_claims` | 标准声明类型非法 |
| `expired` | `exp` 早于当前时间减去 30 秒容差 |
| `not_yet_valid` | `nbf` 晚于当前时间加 30 秒容差 |
| `bad_iss` | 签发方与配置不符 |
| `bad_aud` | 受众不包含期望的客户端标识 |

## 包结构

- `jwtverify/decoder.py` — 三段拆分、base64url 解码（无填充、`-_` 变体），错误以返回值传递
- `jwtverify/claims.py` — 标准声明解析与类型检查
- `jwtverify/algorithms.py` — HS256/HS384 白名单、HMAC 签名与常量时间比较
- `jwtverify/keys.py` — 密钥配置加载、kid 校验（不拼路径）
- `jwtverify/validator.py` — 单条令牌的完整判定流水线
- `jwtverify/report.py` — JSON 报告与摘要
- `jwtverify/cli.py` / `jwtverify/__main__.py` — 命令行入口

