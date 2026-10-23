<p align="center"><a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> · <b>Türkçe</b> · <a href="README.ar.md">العربية</a></p>
<p align="center">Video eğitimleri: <a href="https://www.youtube.com/@pwfauth">youtube.com/@pwfauth</a></p>

# pwfauth

## 1.5.0 sürümünü kurun

1.5.0, **kullanıcı değişkenlerini** getiriyor: programınızın her müşteri için sunucuda sakladığı ve panelden düzenlenebilen değerler (`set_variable`, `get_variable`, `get_variables`, `delete_variable`). Ayrıntılar için [CHANGELOG.md](CHANGELOG.md) dosyasına bakın


PWF Auth, yanıtlarını yeni bir anahtarla imzalıyor. pwfauth 1.3.0 ve sonraki sürümler bu anahtarı sabitler (pinning); **1.2.0 mevcut sunucuyla iletişim kuramaz**, bu yüzden güncelleyin:

```sh
python -m pip install --upgrade pwfauth==1.5.0
```

1.4.0, pwfauth.com adını engelleyen ağlarda da (BAE'deki Etisalat gibi) çalışır: hiç yanıt alamadığında aynı isteği `https://pwfauth.net` üzerinden aynı sunucuya gönderir. 1.3.1 ise herhangi bir yanıt gelmeden bağlantı koptuğunda (Windows hatası 10054) isteği bir kez daha gönderir. Ayrıntılar için [CHANGELOG.md](CHANGELOG.md) dosyasına bakın

## Sunucu kimlik doğrulama güncellemesi

Hatalar ve saat düzeltme yanıtları dahil tüm yanıtlar, sabitlenmiş PWFAuth açık anahtarıyla doğrulanan geçerli bir RSA-SHA256 imzası taşımalıdır. İmzalamada kullanılan özel anahtar sunucuda kalır ve uygulama gizli anahtarını (app secret) bilmek bu imzayı taklit etmeye yetmez. Her seferinde yeni üretilen rastgele bir nonce, her yanıtı kendi isteğine, metoduna, yoluna, HTTP durum koduna ve gövdenin birebir baytlarına bağlar (PWF-REPLY-V1). Sorgu dizeleri (query string) V1'de imzalanan yolun parçası değildir; üretim ortamında bunları aktarım sırasında HTTPS korur

SDK yalnızca `https://pwfauth.com` adresini kabul eder. Varsayılan aktarım katmanı TLS sertifikalarını doğrular ve yönlendirmeleri reddeder. İmza eksik ya da geçersizse, JSON ayrıştırılmadan veya zarfın şifresi çözülmeden önce işlem güvenli biçimde başarısız olur (fail closed); imzasız proxy/CDN hataları güvenlik hatası sayılır. Eski imzasız protokole geri dönüş yoktur. Önce sunucuyu, ardından istemcileri güncelleyin. Uygulamalar bir güvenlik ya da aktarım hatasından sonra hiçbir işlevin kilidini açmamalıdır

Bu önlem sunucu taklidine (server emulation) karşı koruma sağlar. İstemci makinesini kontrol eden bir saldırganın uygulamanın kendisini değiştirmesini ise engellemez. Değerli işlemlerde son sözü sunucuya bırakın ve gerçek uygulama gizli anahtarlarını herkese açık depolara koymayın


[PWF Auth](https://pwfauth.com) için resmi Python istemcisi. Kapsadıkları:

- lisans anahtarları ve donanım kimliği (HWID) bağlama;
- sunucu tarafından yönetilen uzaktan durdurma (kill switch) ile şifreli oturumlar;
- kullanıcıların cihaz değişikliğini kendilerinin yapabilmesi;
- lisans anahtarlarıyla çalışan hesaplar;
- ücretsiz denemeler, uzaktan yönetilen metinler ve slaytlar, OTA güncelleme kontrolleri

PWF Auth **%100 ücretsizdir**: her özellik, sınırsız, sonsuza dek

```bash
pip install pwfauth
```

Python 3.9+ gerekir. Tek bağımlılık `cryptography`'dir, çünkü Python'un standart kütüphanesinde AES yoktur. HTTP için `requests` yerine standart kütüphanedeki `urllib` kullanılır

## 1.1.0 sürümündeki yenilikler

- **Uzaktan durdurma atlatılamaz.** Sunucunun yanıtı olarak yalnızca şifreli yanıt kabul edilir
  - Düz bir ret artık oturumu sonsuza dek açık tutmaz. En yaygın örnek, 5 dakikadan fazla ileri ya da geri alınmış bir saati sunucunun reddetmesidir
  - Sahte bir `{"success": true}` de oturumu açık tutmaz
  - Yasaklama, duraklatma ve süre bitimi, oturumu sunucunun kendi koduyla (`BANNED`, `PAUSED`, `EXPIRED`…) ve mesajıyla sonlandırır
- **Yanlış PC saati kendini düzeltir.** Sunucu saati reddettiğinde istemci, sunucunun saatine göre fark kadar kaydırma yapar ve bir kez yeniden dener. Kapatmak için `auto_correct_clock=False` kullanın
- **Lisansı yeni bir PC'ye taşıma:** `reset_hardware_id(key, reason)`
- **Lisans anahtarlarıyla çalışan hesaplar:** `register_account_with_key()` ve `redeem_key()`
- **Düzeltmeler:**
  - `check_update()`, `change_account_password()` ve `track_social_click()` 1.0.x sürümlerinde sunucu tarafından reddediliyordu
  - Düzenli kontrol (heartbeat) artık sunucunun belirlediği aralığı kullanır
- Ayrıntılar ve birkaç davranış değişikliği için [CHANGELOG.md](CHANGELOG.md) dosyasına bakın

## Hızlı başlangıç

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

`start_heartbeat()`, tek seferlik bir kontrolü canlı bir oturuma dönüştürür. Anahtarı panelinizden iptal ettiğinizde `on_session_ended`, bir sonraki açılışı beklemeden, tek bir heartbeat aralığı içinde kullanıcının makinesinde tetiklenir. Bir konsol uygulaması veya servis bunun yerine `client.run_heartbeat()` çağırabilir; bu çağrı oturum bitene kadar geri dönmez

### GUI uygulamaları

`on_session_ended`, heartbeat'in arka plan iş parçacığında çalışır. İşi, kullandığınız arayüz araç takımının kendi iş parçacığına aktarın:

```python
client.on_session_ended = lambda code, msg: root.after(0, sign_out, code, msg)   # Tkinter
```

## Lisansı yeni bir PC'ye taşıma

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

Taşıma işlemi anahtarın tüm makinelerle bağını kaldırır ve oturumlarını sonlandırır. Müşterilerin anahtarlarını kendilerinin taşıyıp taşıyamayacağına ve iki taşıma arasındaki bekleme süresine (varsayılan 12 saat) App Settings'te siz karar verirsiniz

## Hesaplar

```python
client.register_account("bob", "S3cret!pass", email="bob@example.com")
client.register_account_with_key("bob", "S3cret!pass", key)   # when the app wants a key at sign-up
client.account_login("bob", "S3cret!pass")                    # opens a session, like login()
client.redeem_key(another_key)                                # adds the key's time to the account
client.change_account_password("bob", "S3cret!pass", "N3w!pass")
```

- **Hesaplardaki anahtarlar:** Kayıt için kullanılan ya da bir hesaba eklenen (redeem) anahtar tükenmiş sayılır. Artık tek başına oturum açmak için kullanılamaz ve bu anahtarla yapılan `login` çağrısı `KEY_REDEEMED` döndürür
- **Parola değişiklikleri:** Parolayı değiştirmek, hesabın tüm cihazlardaki oturumlarını kapatır

## Lisansı okuma

```python
lic = login.license
if lic.is_lifetime:
    print("Lifetime licence")
else:
    print(f"Expires {lic.expires_at:%Y-%m-%d} — {lic.days_remaining} day(s) left")
```

Ömür boyu anahtarlarda `expires_at` değeri `None` olur, çünkü sunucu `expires_at: null` gönderir. Bunu bir tarih gibi ele almak, bu API ile entegrasyonda en sık yapılan hatadır; `is_lifetime` bayrağı da tam olarak bununla hiç uğraşmamanız için vardır

## Özellik bayrakları

```python
if login.get_boolean("pro_export"):
    enable_export()
```

Panelin saklayabildiği `1` / `0` / `"true"` biçimlerinin hepsini doğru yorumlar

## Cihaz hakkı kullanmadan anahtar kontrolü

```python
status = client.check_key(key)   # no session opened, no seat consumed
```

## Güncellemeler

```python
upd = client.check_update("1.4.2")            # channel="beta" / "alpha" also work
if upd.data.get("update_available"):
    print("New version:", upd.data["update"]["version"], upd.data["update"]["download_url"])
```

## Donanım kimliği

```python
from pwfauth import get_hardware_id
print(get_hardware_id())
```

Kimlik, [.NET](https://www.nuget.org/packages/PWFAuth) ve [Node](https://www.npmjs.com/package/pwfauth) istemcilerindekiyle aynı şekilde üretilir. Bu nedenle **aynı makine hangi SDK ile olursa olsun tek cihaz sayılır** ve dil değiştirmek, lisansın cihaz sınırından ikinci bir cihaz hakkı harcamaz

## Diğer her şey

| Metot | Ne yapar |
| --- | --- |
| `login(key)` / `logout()` | Oturumu açar ve kapatır (logout anahtarın bağını kaldırmaz) |
| `check_key(key)` | Oturum açmadan bir anahtarın durumunu okur |
| `heartbeat()` | Elle tek bir heartbeat gönderir |
| `start_heartbeat()` / `stop_heartbeat()` / `run_heartbeat()` | Heartbeat döngüsü |
| `reset_hardware_id(key, reason)` | Lisansı bu PC'ye taşır (kullanıcının kendisi yapar) |
| `create_trial()` | Bu makine için ücretsiz deneme oluşturur |
| `get_app_info()` / `get_texts()` / `get_slides()` | Uzaktan yönetilen uygulama içeriği |
| `set_variable(name, value)` / `get_variable(name)` / `get_variables()` / `delete_variable(name)` | Bu müşteri için sunucuda saklanan değerler (reddedildiğinde `PwfRefusedError` fırlatır) |
| `check_update(version, channel)` | OTA güncelleme kontrolü |
| `track_social_click(link_id)` | Uygulamanın sosyal medya bağlantılarından birine yapılan tıklamayı sayar |
| `register_account()` / `register_account_with_key()` / `account_login()` | Kullanıcı hesapları |
| `redeem_key(key)` / `change_account_password()` | Hesap anahtarları ve parolalar |
| `post_envelope()` / `get_envelope()` / `post_plain()` | Ham aktarım yöntemleri |

### Seçenekler

`PwfClient` şu anahtar sözcük argümanlarını (keyword arguments) alır:

| Seçenek | Etkisi |
| --- | --- |
| `base_url` | `https://pwfauth.com` olarak sabittir; başka adresler reddedilir |
| `heartbeat_seconds` | Heartbeat'ler arasındaki süre; varsayılan olarak sunucunun belirlediği değer |
| `max_heartbeat_failures` | `NETWORK_LOST` öncesinde şifreli yanıt alınamayan ardışık heartbeat sayısı; varsayılan 3 |
| `max_rate_limited_beats` | HTTP 429 için ayrı sınır; varsayılan 10 |
| `timeout` | İstek zaman aşımı |
| `hardware_id` | Kendi donanım kimliğinizi kullanmanızı sağlar |
| `user_agent` | Gönderilecek `User-Agent` başlığı |
| `auto_correct_clock` | Yanlış PC saatini otomatik olarak düzeltir |

## Hatalar

```python
from pwfauth import PwfErrorCodes, PwfHttpError, PwfSecurityError, ends_session

try:
    login = client.login(key)
except PwfSecurityError:
    ...   # an unencrypted "success": not the license server — never unlock on it
except PwfHttpError as e:
    ...   # no usable reply; e.status is 401 for a wrong app secret, 0 for no connection
```

`ends_session(code)`, bir kodun lisansın bu makinede sona erdiği anlamına gelip gelmediğini söyler. Tanımadığı bir kod için bilerek `False` döndürür. Bilinmeyen bir kodun yeni bir geçici durum olma ihtimali, yeni bir yasaklama yolu olma ihtimalinden çok daha yüksektir; ödeme yapan bir kullanıcıyı tahmine dayanarak dışarıda bırakmak ise daha kötü bir hatadır

## Bağlantılar

- [Panel](https://pwfauth.com) · [Belgeler](https://pwfauth.com/docs) · [API başvurusu](https://pwfauth.com/api-reference)
- [.NET istemcisi](https://www.nuget.org/packages/PWFAuth) · [Node istemcisi](https://www.npmjs.com/package/pwfauth) · [VS Code eklentisi](https://marketplace.visualstudio.com/items?itemName=PWFAuth.pwfauth)
- [Kaynak kod](https://github.com/pwfauth/pwfauth-python) · [Discord](https://discord.gg/hX3ZV2ZtMp)

Lisans: MIT
