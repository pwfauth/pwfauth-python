<p align="center"><a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> · <a href="README.tr.md">Türkçe</a> · <b>العربية</b></p>
<p align="center">شروحات بالفيديو: <a href="https://www.youtube.com/@pwfauth">youtube.com/@pwfauth</a></p>

# مكتبة pwfauth

## تثبيت الإصدار 1.5.0

يضيف الإصدار 1.5.0 **متغيرات المستخدم**: قيم يحفظها برنامجك على الخادم لكل عميل (`set_variable`، `get_variable`، `get_variables`، `delete_variable`) ويمكن تعديلها من لوحة التحكم. التفاصيل في [CHANGELOG.md](CHANGELOG.md)


يوقّع PWF Auth ردوده بمفتاح جديد. تثبّت مكتبة pwfauth هذا المفتاح بداخلها (pinning) بدءاً من الإصدار 1.3.0، أما **الإصدار 1.2.0 فلا يستطيع التواصل مع الخادم الحالي**، لذا حدّث المكتبة:

```sh
python -m pip install --upgrade pwfauth==1.5.0
```

يعمل الإصدار 1.4.0 على الشبكات التي تحجب اسم النطاق pwfauth.com (مثل شبكة اتصالات في الإمارات): عندما لا يصله أي رد إطلاقاً، يرسل الطلب نفسه إلى الخادم نفسه عبر `https://pwfauth.net`. ويعيد الإصدار 1.3.1 إرسال الطلب مرة واحدة إذا انقطع الاتصال قبل وصول أي رد (خطأ Windows رقم 10054). التفاصيل في [CHANGELOG.md](CHANGELOG.md)

## تحديث مصادقة الخادم

يجب أن تحمل كل الردود، بما فيها ردود الأخطاء وردود تصحيح الساعة، توقيعاً صالحاً بخوارزمية RSA-SHA256 يُتحقق منه بمفتاح PWFAuth العام المثبّت في المكتبة. يبقى مفتاح التوقيع الخاص على الخادم، ومعرفة سر التطبيق وحدها لا تكفي لتزوير هذا التوقيع. ويربط رقم عشوائي جديد (nonce) كل رد بطلبه وبطريقة الطلب ومساره وحالة HTTP وبايتات المحتوى كما هي تماماً (PWF-REPLY-V1). سلاسل الاستعلام (query strings) ليست جزءاً من المسار الموقّع في V1، ويحميها HTTPS أثناء النقل في بيئة الإنتاج

لا تقبل المكتبة إلا `https://pwfauth.com`. تتحقق وسيلة النقل الافتراضية من شهادات TLS وترفض إعادة التوجيه. عند غياب التوقيع أو عدم صحته يُرفض الرد بأمان (fail closed) قبل تحليل JSON أو فك تشفير الغلاف، وتُعامَل أخطاء الوكيل أو CDN غير الموقّعة على أنها أخطاء أمنية. لا رجوع إلى البروتوكول القديم غير الموقّع. حدّث الخادم قبل العملاء. ويجب ألا يفتح التطبيق أي ميزة بعد خطأ أمني أو خطأ في النقل

يحمي هذا من محاكاة الخادم (server emulation)، لكنه لا يمنع مهاجماً يتحكم بجهاز العميل من تعديل التطبيق نفسه. اجعل العمليات المهمة ذات القيمة تُنفَّذ على الخادم وهو صاحب القرار فيها، ولا تضع أسرار تطبيقاتك الحقيقية في مستودعات عامة


هذا هو العميل الرسمي بلغة Python لخدمة [PWF Auth](https://pwfauth.com)، ويغطي:

- مفاتيح الترخيص وربطها بمعرّف الجهاز (HWID)؛
- جلسات مشفّرة مع الإيقاف عن بُعد الذي يتحكم به الخادم؛
- نقل الترخيص إلى جهاز جديد يقوم به المستخدم بنفسه؛
- حسابات تعمل بمفاتيح الترخيص؛
- النسخ التجريبية المجانية، والنصوص والشرائح التي تُدار عن بُعد، والتحقق من التحديثات (OTA)

خدمة PWF Auth **مجانية 100%**: كل الميزات، بلا حدود، وإلى الأبد

```bash
pip install pwfauth
```

تحتاج المكتبة إلى Python 3.9 أو أحدث، ولها اعتمادية واحدة فقط هي `cryptography` لأن مكتبة Python القياسية لا تتضمن AES. أما طلبات HTTP فتستخدم `urllib` من المكتبة القياسية بدلاً من `requests`

## الجديد في الإصدار 1.1.0

- **لا يمكن التهرب من الإيقاف عن بُعد.** لا يُعتدّ بأي رد من الخادم إلا إذا كان مشفّراً
  - لم يعد الرفض العادي يُبقي الجلسة حية إلى الأبد. وأشيع حالاته رفض الخادم لساعة جهاز عُدّلت بأكثر من 5 دقائق
  - ولا يُبقيها أيضاً رد مزيف مثل `{"success": true}`
  - الحظر والإيقاف المؤقت وانتهاء الصلاحية تنهي الجلسة برمز الخادم نفسه (`BANNED`، `PAUSED`، `EXPIRED`…) وبرسالته
- **ساعة الجهاز الخاطئة تُصلح نفسها.** عندما يرفض الخادم الوقت، يصحّح العميل وقته بحسب ساعة الخادم ويعيد المحاولة مرة واحدة. ولإيقاف ذلك استخدم `auto_correct_clock=False`
- **نقل الترخيص إلى جهاز جديد:** `reset_hardware_id(key, reason)`
- **حسابات تعمل بمفاتيح الترخيص:** `register_account_with_key()` و`redeem_key()`
- **إصلاحات:**
  - كان الخادم يرفض `check_update()` و`change_account_password()` و`track_social_click()` في الإصدارات 1.0.x
  - يستخدم التحقق الدوري (heartbeat) الآن الفاصل الزمني الذي يحدده الخادم
- راجع [CHANGELOG.md](CHANGELOG.md) للتفاصيل وللتغييرات القليلة في السلوك

## البدء السريع

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

الدالة `start_heartbeat()` هي ما يحوّل التحقق الذي يجري مرة واحدة إلى جلسة حية. ألغِ المفتاح من لوحة التحكم، وسيُستدعى `on_session_ended` على جهاز المستخدم خلال دورة واحدة من التحقق الدوري دون انتظار التشغيل التالي. ويمكن لتطبيق سطر الأوامر (Console) أو الخدمة استدعاء `client.run_heartbeat()` بدلاً منها، وهي لا تعود حتى تنتهي الجلسة

### تطبيقات الواجهة الرسومية (GUI)

يعمل `on_session_ended` على مؤشر الترابط الخلفي للتحقق الدوري، لذا انقل العمل إلى مؤشر ترابط مكتبة الواجهة نفسها:

```python
client.on_session_ended = lambda code, msg: root.after(0, sign_out, code, msg)   # Tkinter
```

## نقل الترخيص إلى جهاز جديد

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

يفك النقل ارتباط المفتاح بكل الأجهزة وينهي جلساته. ومن صفحة App Settings تحدد ما إذا كان العملاء يستطيعون نقل مفاتيحهم بأنفسهم، ومدة الانتظار بين عمليتي نقل (12 ساعة افتراضياً)

## الحسابات

```python
client.register_account("bob", "S3cret!pass", email="bob@example.com")
client.register_account_with_key("bob", "S3cret!pass", key)   # when the app wants a key at sign-up
client.account_login("bob", "S3cret!pass")                    # opens a session, like login()
client.redeem_key(another_key)                                # adds the key's time to the account
client.change_account_password("bob", "S3cret!pass", "N3w!pass")
```

- **المفاتيح على الحسابات:** المفتاح الذي يُستخدم لإنشاء حساب أو يُضاف إلى حساب يُستهلك، فلا يمكن بعدها تسجيل الدخول به وحده، ويرد `login` بهذا المفتاح بالرمز `KEY_REDEEMED`
- **تغيير كلمة المرور:** يؤدي تغيير كلمة المرور إلى تسجيل خروج الحساب من كل الأجهزة

## قراءة الترخيص

```python
lic = login.license
if lic.is_lifetime:
    print("Lifetime licence")
else:
    print(f"Expires {lic.expires_at:%Y-%m-%d} — {lic.days_remaining} day(s) left")
```

القيمة `expires_at` تساوي `None` لمفاتيح مدى الحياة، لأن الخادم يرسل `expires_at: null`. والتعامل معها على أنها تاريخ هو أشيع خطأ عند التكامل مع هذه الواجهة البرمجية، والخاصية `is_lifetime` موجودة كي لا تضطر إلى ذلك أبداً

## مفاتيح الميزات (Feature flags)

```python
if login.get_boolean("pro_export"):
    enable_export()
```

تتعامل الدالة مع الصيغ `1` / `0` / `"true"` التي قد تخزنها لوحة التحكم

## التحقق من مفتاح دون استهلاك جهاز من الأجهزة المسموح بها

```python
status = client.check_key(key)   # no session opened, no seat consumed
```

## التحديثات

```python
upd = client.check_update("1.4.2")            # channel="beta" / "alpha" also work
if upd.data.get("update_available"):
    print("New version:", upd.data["update"]["version"], upd.data["update"]["download_url"])
```

## معرّف الجهاز

```python
from pwfauth import get_hardware_id
print(get_hardware_id())
```

يُحسب المعرّف بالطريقة نفسها المتبعة في عميلَي [.NET](https://www.nuget.org/packages/PWFAuth) و[Node](https://www.npmjs.com/package/pwfauth). لذلك **يُحتسب الجهاز نفسه جهازاً واحداً مع أي SDK**، والانتقال إلى لغة برمجة أخرى لا يستهلك جهازاً ثانياً من حد الأجهزة في الترخيص

## كل ما تبقى

| الدالة | ما تفعله |
| --- | --- |
| `login(key)` / `logout()` | فتح الجلسة وإغلاقها (تسجيل الخروج لا يفك ارتباط المفتاح بالجهاز) |
| `check_key(key)` | قراءة حالة المفتاح دون فتح جلسة |
| `heartbeat()` | دورة تحقق يدوية واحدة |
| `start_heartbeat()` / `stop_heartbeat()` / `run_heartbeat()` | حلقة التحقق الدوري |
| `reset_hardware_id(key, reason)` | نقل الترخيص إلى هذا الجهاز (يقوم به المستخدم بنفسه) |
| `create_trial()` | إصدار نسخة تجريبية مجانية لهذا الجهاز |
| `get_app_info()` / `get_texts()` / `get_slides()` | محتوى التطبيق الذي يُدار عن بُعد |
| `set_variable(name, value)` / `get_variable(name)` / `get_variables()` / `delete_variable(name)` | قيم تُحفظ على الخادم لهذا العميل (ترمي الاستثناء `PwfRefusedError` عند الرفض) |
| `check_update(version, channel)` | التحقق من التحديثات (OTA) |
| `track_social_click(link_id)` | احتساب نقرة على أحد روابط التطبيق في الشبكات الاجتماعية |
| `register_account()` / `register_account_with_key()` / `account_login()` | حسابات المستخدمين |
| `redeem_key(key)` / `change_account_password()` | مفاتيح الحسابات وكلمات مرورها |
| `post_envelope()` / `get_envelope()` / `post_plain()` | وسائل النقل الخام |

### الخيارات

يقبل `PwfClient` المعاملات المسماة (keyword arguments) التالية:

| الخيار | التأثير |
| --- | --- |
| `base_url` | ثابت على `https://pwfauth.com`، ويُرفض أي عنوان آخر |
| `heartbeat_seconds` | الفاصل بين دورات التحقق الدوري، وهو فاصل الخادم افتراضياً |
| `max_heartbeat_failures` | عدد الدورات المتتالية دون رد مشفّر قبل `NETWORK_LOST`، وهو 3 افتراضياً |
| `max_rate_limited_beats` | حد منفصل لردود HTTP 429، وهو 10 افتراضياً |
| `timeout` | مهلة الطلب |
| `hardware_id` | استخدام معرّف جهاز تحدده بنفسك |
| `user_agent` | قيمة الترويسة `User-Agent` المرسلة |
| `auto_correct_clock` | إصلاح ساعة الجهاز الخاطئة تلقائياً |

## الأخطاء

```python
from pwfauth import PwfErrorCodes, PwfHttpError, PwfSecurityError, ends_session

try:
    login = client.login(key)
except PwfSecurityError:
    ...   # an unencrypted "success": not the license server — never unlock on it
except PwfHttpError as e:
    ...   # no usable reply; e.status is 401 for a wrong app secret, 0 for no connection
```

تخبرك الدالة `ends_session(code)` ما إذا كان الرمز يعني أن الترخيص انتهى على هذا الجهاز، وهي تعيد `False` عمداً لأي رمز لا تعرفه. فالرمز المجهول أرجح بكثير أن يكون حالة مؤقتة جديدة من أن يكون طريقة جديدة للحظر، وإغلاق التطبيق في وجه مستخدم يدفع بناءً على تخمين هو الخطأ الأسوأ

## روابط

- [لوحة التحكم](https://pwfauth.com) · [التوثيق](https://pwfauth.com/docs) · [مرجع API](https://pwfauth.com/api-reference)
- [عميل .NET](https://www.nuget.org/packages/PWFAuth) · [عميل Node](https://www.npmjs.com/package/pwfauth) · [إضافة VS Code](https://marketplace.visualstudio.com/items?itemName=PWFAuth.pwfauth)
- [الشيفرة المصدرية](https://github.com/pwfauth/pwfauth-python) · [Discord](https://discord.gg/hX3ZV2ZtMp)

الرخصة: MIT
