<p align="center"><a href="README.md">English</a> · <b>简体中文</b> · <a href="README.tr.md">Türkçe</a> · <a href="README.ar.md">العربية</a></p>
<p align="center">视频教程：<a href="https://www.youtube.com/@pwfauth">youtube.com/@pwfauth</a></p>

# pwfauth

## 安装 1.5.0

1.5.0 新增**用户变量**：程序为每位客户保存在服务器上的值（`set_variable`、`get_variable`、`get_variables`、`delete_variable`），可在后台中编辑。详见 [CHANGELOG.md](CHANGELOG.md)


PWF Auth 现在使用新的密钥为回复签名。pwfauth 1.3.0 及更新版本内置并固定（pin）了对应的公钥；**1.2.0 已无法与当前服务器通信**，请升级：

```sh
python -m pip install --upgrade pwfauth==1.5.0
```

1.4.0 可以在屏蔽 pwfauth.com 域名的网络（例如阿联酋的 Etisalat）中正常工作：完全收不到回复时，同一请求会通过 `https://pwfauth.net` 发往同一台服务器。1.3.1 在收到任何回复之前连接就断开时（Windows 错误 10054）会再发送一次请求。详见 [CHANGELOG.md](CHANGELOG.md)

## 服务器认证更新

所有响应，包括错误响应和时钟校正响应，都必须带有有效的 RSA-SHA256 签名，并能通过内置固定的 PWFAuth 公钥验证。签名私钥只保存在服务器上，仅凭应用密钥（app secret）无法伪造该签名。每个响应都通过一个全新的随机 nonce 与对应的请求、方法、路径、HTTP 状态码以及响应体的原始字节绑定（PWF-REPLY-V1）。查询字符串不属于 V1 签名路径的一部分，生产环境中由 HTTPS 保证其传输安全

SDK 只接受 `https://pwfauth.com`。默认传输层会校验 TLS 证书并拒绝重定向。签名缺失或无效时，会在解析 JSON 或解密信封之前直接失败（fail closed）；未签名的代理或 CDN 错误一律视为安全错误。不会回退到旧的未签名协议。请先升级服务器，再升级客户端。出现安全错误或传输错误后，应用绝不能解锁任何功能

这一机制防范的是服务器模拟，但无法阻止控制了客户端机器的攻击者修改应用本身。请把有价值的关键操作放在服务器端处理，并且不要把真实的应用密钥放进公开仓库


[PWF Auth](https://pwfauth.com) 的官方 Python 客户端，功能包括：

- 许可证密钥与硬件 ID（HWID）绑定；
- 加密会话，以及由服务器控制的远程停用（kill switch）；
- 用户自助迁移设备；
- 基于许可证密钥的账户；
- 免费试用、远程文本和幻灯片，以及 OTA 更新检查

PWF Auth **100% 免费**：全部功能，不限量，永久免费

```bash
pip install pwfauth
```

需要 Python 3.9+。唯一的依赖是 `cryptography`，因为 Python 标准库中没有 AES。HTTP 请求使用标准库中的 `urllib`，而不是 `requests`

## 1.1.0 新特性

- **远程停用无法被绕过**。只有加密的回复才算作服务器的应答
  - 普通的拒绝响应不会再让会话永远保持有效。最常见的情况是服务器拒绝了被调整超过 5 分钟的时钟
  - 伪造的 `{"success": true}` 同样不行
  - 封禁、暂停和过期会以服务器自己的错误码（`BANNED`、`PAUSED`、`EXPIRED`…）和消息结束会话
- **错误的电脑时钟会自动修正**。服务器拒绝时间时，客户端会按服务器时钟校正偏差并重试一次。可通过 `auto_correct_clock=False` 关闭
- **将许可证迁移到新电脑**：`reset_hardware_id(key, reason)`
- **基于许可证密钥的账户**：`register_account_with_key()` 和 `redeem_key()`
- **修复**：
  - 在 1.0.x 中，`check_update()`、`change_account_password()` 和 `track_social_click()` 会被服务器拒绝
  - 心跳现在使用服务器下发的间隔
- 详细信息以及少数行为变更请参阅 [CHANGELOG.md](CHANGELOG.md)

## 快速开始

```python
import os
import sys
from pwfauth import PwfClient

client = PwfClient(os.environ["PWFAUTH_SECRET"])

def on_session_ended(error_code, message):
    """Ban, pause, expiry, HWID reset, revoke, maintenance, or a server that stopped
    answering. Actually stop here — logging alone leaves the licence unenforceable.
    This runs on the heartbeat thread, so os._exit (sys.exit would only end it)."""
    print(f"Session ended ({error_code}): {message}", file=sys.stderr)
    os._exit(1)

client.on_session_ended = on_session_ended

login = client.login("XXXXX-XXXXX-XXXXX-XXXXX")
if not login.success:
    print(login.message, file=sys.stderr)   # safe to show the user
    sys.exit(1)

client.start_heartbeat()   # keeps the session alive AND enforces the kill switch
```

`start_heartbeat()` 会把一次性检查变成持续在线的会话。在后台吊销该密钥后，用户机器上的 `on_session_ended` 会在一个心跳周期内触发，不必等到下次启动。控制台应用或服务可以改为调用 `client.run_heartbeat()`，它会一直阻塞到会话结束

### GUI 应用

`on_session_ended` 运行在心跳的后台线程上。请把后续工作交给所用 GUI 工具包自己的线程处理：

```python
client.on_session_ended = lambda code, msg: root.after(0, sign_out, code, msg)   # Tkinter
```

## 将许可证迁移到新电脑

```python
from pwfauth import PwfErrorCodes

login = client.login(key)
if login.error_code in (PwfErrorCodes.HWID_MISMATCH, PwfErrorCodes.DEVICE_LIMIT):
    if ask_user("This key is used on another computer. Move it here?"):
        moved = client.reset_hardware_id(key, "New laptop")
        if moved.success:
            login = client.login(key)
        else:
            show(moved.message)   # e.g. the cooldown: "try again in 11 hours"
```

迁移会解除密钥与所有机器的绑定，并结束它的所有会话。你可以在 App Settings 中决定客户能否自行迁移密钥，以及两次迁移之间的冷却时间（默认 12 小时）

## 账户

```python
client.register_account("bob", "S3cret!pass", email="bob@example.com")
client.register_account_with_key("bob", "S3cret!pass", key)   # when the app wants a key at sign-up
client.account_login("bob", "S3cret!pass")                    # opens a session, like login()
client.redeem_key(another_key)                                # adds the key's time to the account
client.change_account_password("bob", "S3cret!pass", "N3w!pass")
```

- **账户上的密钥**：用于注册或兑换到账户上的密钥即被消耗，之后不能再单独用于登录，用它调用 `login` 会返回 `KEY_REDEEMED`
- **修改密码**：修改密码会让该账户在所有设备上退出登录

## 读取许可证信息

```python
lic = login.license
if lic.is_lifetime:
    print("Lifetime licence")
else:
    print(f"Expires {lic.expires_at:%Y-%m-%d} — {lic.days_remaining} day(s) left")
```

对于永久密钥，`expires_at` 为 `None`，因为服务器发送的是 `expires_at: null`。把它当作日期处理是对接这个 API 时最常见的错误，`is_lifetime` 标志正是为了让你完全不必这样做

## 功能开关

```python
if login.get_boolean("pro_export"):
    enable_export()
```

可正确处理后台可能存储的 `1` / `0` / `"true"` 等形式

## 检查密钥而不占用设备名额

```python
status = client.check_key(key)   # no session opened, no seat consumed
```

## 更新

```python
upd = client.check_update("1.4.2")            # channel="beta" / "alpha" also work
if upd.data.get("update_available"):
    print("New version:", upd.data["update"]["version"], upd.data["update"]["download_url"])
```

## 硬件 ID

```python
from pwfauth import get_hardware_id
print(get_hardware_id())
```

该 ID 的生成方式与 [.NET](https://www.nuget.org/packages/PWFAuth) 和 [Node](https://www.npmjs.com/package/pwfauth) 客户端完全一致。因此**同一台机器在任何 SDK 下都只算一台设备**，更换编程语言也不会额外占用许可证设备上限中的第二个名额

## 其他方法

| 方法 | 作用 |
| --- | --- |
| `login(key)` / `logout()` | 打开和关闭会话（logout 不会解除密钥绑定） |
| `check_key(key)` | 不开启会话，直接读取密钥状态 |
| `heartbeat()` | 手动发送一次心跳 |
| `start_heartbeat()` / `stop_heartbeat()` / `run_heartbeat()` | 心跳循环 |
| `reset_hardware_id(key, reason)` | 将许可证迁移到本机（用户自助） |
| `create_trial()` | 为本机发放免费试用 |
| `get_app_info()` / `get_texts()` / `get_slides()` | 远程应用内容 |
| `set_variable(name, value)` / `get_variable(name)` / `get_variables()` / `delete_variable(name)` | 为该客户保存在服务器上的值（被拒绝时抛出 `PwfRefusedError`） |
| `check_update(version, channel)` | OTA 更新检查 |
| `track_social_click(link_id)` | 统计应用某个社交链接的点击次数 |
| `register_account()` / `register_account_with_key()` / `account_login()` | 用户账户 |
| `redeem_key(key)` / `change_account_password()` | 账户密钥与密码 |
| `post_envelope()` / `get_envelope()` / `post_plain()` | 底层传输 |

### 选项

`PwfClient` 接受以下关键字参数：

| 选项 | 作用 |
| --- | --- |
| `base_url` | 固定为 `https://pwfauth.com`，其他地址一律拒绝 |
| `heartbeat_seconds` | 心跳间隔，默认使用服务器的设置 |
| `max_heartbeat_failures` | 连续多少次心跳未收到加密应答后触发 `NETWORK_LOST`，默认 3 次 |
| `max_rate_limited_beats` | 针对 HTTP 429 单独计算的次数上限，默认 10 次 |
| `timeout` | 请求超时时间 |
| `hardware_id` | 使用自定义的硬件 ID |
| `user_agent` | 要发送的 `User-Agent` 请求头 |
| `auto_correct_clock` | 自动修正错误的电脑时钟 |

## 错误处理

```python
from pwfauth import PwfErrorCodes, PwfHttpError, PwfSecurityError, ends_session

try:
    login = client.login(key)
except PwfSecurityError:
    ...   # an unencrypted "success": not the license server — never unlock on it
except PwfHttpError as e:
    ...   # no usable reply; e.status is 401 for a wrong app secret, 0 for no connection
```

`ends_session(code)` 用于判断某个错误码是否意味着许可证在本机已经失效。对于无法识别的错误码，它会刻意返回 `False`。未知错误码更可能是一种新的临时状态，而不是一种新的封禁方式；仅凭猜测就把付费用户拒之门外，才是更糟糕的失败

## 链接

- [后台](https://pwfauth.com) · [文档](https://pwfauth.com/docs) · [API 参考](https://pwfauth.com/api-reference)
- [.NET 客户端](https://www.nuget.org/packages/PWFAuth) · [Node 客户端](https://www.npmjs.com/package/pwfauth) · [VS Code 扩展](https://marketplace.visualstudio.com/items?itemName=PWFAuth.pwfauth)
- [源代码](https://github.com/pwfauth/pwfauth-python) · [Discord](https://discord.gg/hX3ZV2ZtMp)

许可：MIT
