# Mərkəzi Auth Server (vahid bazalı login)

Bu server bütün müştəri quraşdırmaları üçün **tək (vahid)** istifadəçi bazasını saxlayır. Proqram (EXE) login/parolu bura göndərir, server yoxlayır.

## İşə salmaq

```powershell
cd server
python auth_server.py
```

və ya `run_server.bat` faylını işə sal.

İlk işə salındıqda bootstrap admin yaradılır:

- Username: `admin`
- Password: `ChangeMe123!` (ilk girişdə dəyişdirilməlidir)

## Konfiqurasiya (mühit dəyişənləri)

| Dəyişən | Default | İzah |
|---|---|---|
| `CSG_HOST` | `127.0.0.1` | Dinləmə ünvanı. Radmin şəbəkəsi üçün Radmin adapterinin IP-si (məs. `26.x.x.x`) — bax aşağıda "Şəbəkə əhatəsi" |
| `CSG_PORT` | `8777` | Port |
| `CSG_DB` | `server/server_users.db` | SQLite baza yolu |
| `CSG_TOKEN_TTL` | `43200` | Sessiya tokeninin ömrü (saniyə, default 12 saat) |
| `CSG_LATEST_VERSION` | (boş → `latest_version.txt`) | Client-in bilməli olduğu ən son versiya (auto-update bildirişi) |
| `CSG_UPDATE_NOTES` | (boş) | Yeniləmə bildirişində göstəriləcək əlavə qeyd |
| `CSG_LICENSE_WARN_DAYS` | `3` | Lisenziya bitməsinə neçə gün qalanda Telegram xəbərdarlığı göndərilsin |
| `CSG_LOG_FILE` | `server/server.log` | Rotasiya ediləcək log faylının yolu |
| `CSG_LOG_MAX_BYTES` | `5242880` (5MB) | Bu ölçüyə çatanda log `.1`-ə köçürülür və təzədən başlayır |

Nümunə:

```powershell
set CSG_HOST=26.255.229.239
set CSG_PORT=8777
python auth_server.py
```

### Şəbəkə əhatəsi (Radmin-only bind)

`run_server.bat` / `run_server_headless.bat` `CSG_HOST`-u `0.0.0.0` əvəzinə **Radmin VPN adapterinin öz IP-sinə** (`Get-NetIPAddress` ilə tapıla bilər, "Radmin VPN" adapteri) qururlar. Bu, serveri yalnız Radmin şəbəkəsindən əlçatan edir — server maşınının qoşulu olduğu başqa heç bir şəbəkədən (məs. ev/ofis Wi-Fi) əlçatan olmur.

Bununla belə, server avtomatik olaraq **ikinci, yalnız-lokal (`127.0.0.1`) bir "mirror"** də başladır ki, "bu kompüterdə (lokal)" aşkarlaması pozulmasın — bu mirror şəbəkəyə açıq deyil, sırf eyni maşındakı client-in loopback vasitəsilə serverin lokal işlədiyini görməsi üçündür.

Boot zamanı Radmin adapteri hələ IP almamış ola bilər deyə, server bind-i **12 dəfə, 10 saniyə arayla** yenidən cəhd edir (~2 dəqiqəyə qədər).

## Avtomatik başlama (server.bat açmadan)

Windows-a giriş edəndə server **gizli avtomatik** başlasın deyə:

```
install_autostart.bat
```

- Startup qovluğuna gizli VBS launcher qoyur (admin hüququ lazım deyil).
- Loglar: `server\server.log`.
- Firewall qaydası əlavə edir (port 8777, yalnız `26.0.0.0/8` + `127.0.0.1`).
- Watchdog planlaşdırılmış tapşırığı (`TexnikiEkranWatchdog`) qurur — bax aşağıda.
- Ləğv: `uninstall_autostart.bat`.
- Dayandırmaq: Task Manager → `python.exe`.

## Watchdog (avtomatik yenidən başlatma)

Startup-dakı VBS launcher yalnız Windows-a giriş zamanı **bir dəfə** işə düşür — server sonradan çökərsə (yaddaş xətası və s.) özü-özünə yenidən başlamır. Bunun üçün `install_autostart.bat` bir Windows Scheduled Task (`TexnikiEkranWatchdog`) qurur:

- Hər **3 dəqiqədən** bir `watchdog_check.bat` işə düşür.
- `127.0.0.1:8777`-ə qısa TCP testi edir (Radmin-in online/offline vəziyyətindən asılı deyil — sırf prosesin canlı olub-olmadığını yoxlayır).
- Cavab yoxdursa, `watchdog.log`-a qeyd yazır və Startup VBS launcher-i yenidən işə salır.

Əl ilə yoxlamaq: `schtasks /query /tn "TexnikiEkranWatchdog" /v`. Ləğv `uninstall_autostart.bat` ilə (`schtasks /delete`).

## Avtomatik backup

Server hər **6 saatda** `server_users.db`-ni `server\backups\` qovluğuna kopyalayır (son **14** nüsxə saxlanılır). Dəyişmək: `CSG_BACKUP_HOURS`, `CSG_BACKUP_KEEP`.

## Log rotasiyası

`server.log` sərhədsiz böyüməsin deyə, server hər **10 dəqiqədən** bir ölçünü yoxlayır; `CSG_LOG_MAX_BYTES`-i keçəndə cari logu `server.log.1`-ə köçürür (əvvəlki `.1` silinir) və təzə boş `server.log`-a davam edir. Yalnız 1 əvvəlki nüsxə saxlanılır.

## Lisenziya bitmə xəbərdarlığı (Telegram)

Operator Telegram-da botla bir dəfə danışıbsa (`tg_operator` state-i quraşdırılıb), server gündə bir dəfə (UTC günü üzrə) bütün istifadəçiləri yoxlayıb, lisenziyası `CSG_LICENSE_WARN_DAYS` (default 3) gün içində bitəcək və ya artıq bitmiş hesabların siyahısını operatora Telegram mesajı kimi göndərir:

```
📋 Lisenziya hesabatı:
⚠️ musteri1: 2 gün qalıb
🔴 musteri2: müddəti bitib
```

Operator konfiqurasiya olunmayıbsa, heç nə göndərilmir. Eyni gün içində ikinci dəfə göndərilmir.

## HTTPS (vacib)

Server sadə HTTP verir. İnternetdə **mütləq** TLS ilə istifadə et: onu nginx / Caddy kimi reverse proxy arxasına qoy və TLS-i orada bitir.

Nümunə (Caddy):

```
auth.senin-domenin.az {
    reverse_proxy 127.0.0.1:8777
}
```

Sonra proqramın Ayarlar-ında server ünvanını `https://auth.senin-domenin.az` təyin et.

## API (qısa)

| Metod | Yol | İzah |
|---|---|---|
| GET | `/api/health` | Sağlamlıq yoxlaması |
| GET | `/api/version` | Ən son client versiyası: `{version,notes}` (auto-update bildirişi üçün, açardan istisna) |
| GET | `/relay` | WebSocket ekran-paylaşımı relay ucu (adi REST deyil — `Upgrade: websocket` gözləyir): `?token=...&channel=FRAMES\|INPUT\|FILE`, `X-Api-Key` tələb olunur, token `screen_share_sessions`-də doğrulanır (bax `screen_share_token_is_valid`) |
| POST | `/api/login` | `{username,password}` → `{token,user}` |
| POST | `/api/change-password` | `{username,old_password,new_password}` |
| GET | `/api/users` | (admin token) istifadəçi siyahısı |
| POST | `/api/users` | (admin token) əlavə et |
| POST | `/api/users/delete` | (admin token) sil |
| POST | `/api/users/reset-password` | (admin token) parol sıfırla |
| POST | `/api/users/set-active` | (admin token) aktiv/deaktiv |
| POST | `/api/users/set-license` | (admin token) lisenziya ver/uzat/ləğv: `{id,active,days}` |
| GET | `/api/audit` | (admin token) admin əməliyyat tarixçəsi: `?limit=200` → `{entries:[{ts,admin,action,target,detail}]}` |
| GET | `/api/stats` | (admin token) ümumi mənzərə: `{total_users,active_licenses,expiring_soon,expired,warn_days,uptime_seconds}` |
| GET | `/api/commands/poll` | (auth) uzaqdan komandaları alır (`lock/unlock/say`) |
| POST | `/api/remote-access/notify` | (auth) müştərinin RDP uzaqdan-giriş vəziyyətini operatora Telegram ilə çatdırır: `{action:"grant"\|"revoke", ip, username, password, port, expires_minutes}` — hazırda UI-dan çağırılmır (bax aşağıda "Ekran paylaşımı") |
| POST | `/api/screen-share/notify` | (auth) özünə-xidmət ("Başlat") axını üçün müştərinin öz yaratdığı ekran-paylaşımı token-ini qeydə alır: `{action:"start"\|"stop", token}` |
| POST | `/api/connect-code/set` | (auth) müştəri login-dən sonra öz TeamViewer-tərzi ID(username)+Kod-unu qeydə alır: `{code}` |
| POST | `/api/screen-share/connect-by-code` | (admin token) ID+Kodu doğrulayır, token-i BURADA yaradır, müştəriyə uzaqdan `start_screen_share` komandası göndərir VƏ token-i cavabda dərhal qaytarır: `{username, code}` → `{ok, token}` |
| GET | `/api/screen-share/session` | (admin token) özünə-xidmət axını üçün: `?username=X` — müştərinin öz yaratdığı token-i pollayır: `{ready, token}` |
| POST | `/api/screen-share/stop-remote` | (admin token) izləyici pəncərə bağlananda müştəriyə uzaqdan `stop_screen_share` komandası göndərir: `{username}` |
| GET | `/api/admin/chat/list` | (admin token) DƏSTƏK yazmış bütün müştərilər + son mesaj + cavabsız işarəsi: `{chats:[{username,last_text,last_ts,pending}]}` |
| GET | `/api/admin/chat/history` | (admin token) `?username=X` — konkret müştəri ilə tam yazışma: `{messages:[{id,direction,text,ts}]}` |
| POST | `/api/admin/chat/send` | (admin token) konkret müştəriyə proqram-daxili cavab göndərir (Telegram-a ehtiyac yoxdur): `{username, message}` |

Lisenziya `login` cavabında qayıdır: `user.license_active`, `user.license_expires`, `user.license_valid`. Client `license_valid` false olarsa girişi bağlayır (admin istisna).

## Versiya idarəsi — MƏCBURİ avtomatik yeniləmə (GitHub Releases)

`server/latest_version.txt` (və ya `CSG_LATEST_VERSION`/`CSG_UPDATE_NOTES`/`CSG_UPDATE_URL` env dəyişənləri) 3 sətirdən ibarətdir: **1-ci** versiya nömrəsi, **2-ci** (istəyə bağlı) operator qeydi, **3-cü** GitHub Releases-dəki `.exe`-in birbaşa endirmə linki. Fayl **hər `/api/version` sorğusunda təzədən oxunur** — serveri yenidən başlatmadan dərhal təsir edir (kill-switch kimi də işlədilə bilər).

Client hər açılışda `/api/version`-u bir dəfə soruşur:
- **Hazır (frozen) EXE-də** (müştəriyə göndərdiyiniz build): serverdəki versiya öz versiyasından yenidirsə, **məcburi** bir pəncərə açılır (bağlana bilməz, "davam et" seçimi YOXDUR) — yeni exe GitHub-dan avtomatik endirilir, köhnəsi əvəz olunur, proqram özü yenidən başlayır. Müştəri heç nə etmir.
- **Dev rejimində** (`python main.py` birbaşa işə salınıb): yalnız köhnə **passiv** (dismiss oluna bilən) bildiriş zolağı göstərir — proqramçının işini pozmamaq üçün məcburi axın burda İŞLƏMİR.
- Server ümumiyyətlə əlçatan deyilsə (şəbəkə problemi və s.): heç nə göstərilmir, proqram normal davam edir — server nasazlığı müştərini kilidləməməlidir.

### Yeni versiya buraxılışı (release) necə edilir

1. Yeni `main.py` dəyişikliklərini edin, `main.py`-də `APP_VERSION`-u artırın (məs. `"1.0.1"`).
2. `python -m PyInstaller --noconfirm --clean --onefile --windowed --name TexnikiEkran main.py` ilə yeni `dist/TexnikiEkran.exe`-ni qurun.
3. GitHub-da **AYRI, ictimai (public)** bir repo yaradın, YALNIZ buraxılışlar üçün (məs. `TexnikiEkran-Releases`) — qaynaq kodunuzu bura QOYMAYIN, sadəcə hazır exe-lər. İctimai olması vacibdir, əks halda endirmə linki token tələb edər.
4. O repo-da "Releases" → "Draft a new release" → tag `v1.0.1` → `dist/TexnikiEkran.exe`-ni asset olaraq yükləyin → "Publish release".
5. `server/latest_version.txt`-i yeniləyin:
   ```
   1.0.1
   Ekran-paylaşımında sürət yaxşılaşdırıldı
   https://github.com/seyfullazaderesul/TexnikiEkran-Releases/releases/latest/download/TexnikiEkran.exe
   ```
   (3-cü sətirdəki link həmişə eynidir — GitHub "latest" özü avtomatik ən son buraxılışa yönləndirir, hər dəfə dəyişməyə ehtiyac yoxdur, sadəcə asset faylının adı hər release-də **TexnikiEkran.exe** olmalıdır ki, link işləsin.)
6. Bir neçə saniyə sonra bütün açıq müştəri EXE-ləri avtomatik yenilənəcək (server restart lazım deyil).

## Admin audit trail

Bütün admin mutasiya əməliyyatları (`add_user`, `delete_user`, `reset_password`, `set_active`, `set_license`) serverdə `audit_log` cədvəlinə yazılır: **hansı admin, nə vaxt, hansı hesaba qarşı, nə etdi**. Admin Panel-də "🗂 Admin əməliyyatları (server tarixçəsi)" düyməsi bu tarixçəni göstərir (`/api/audit`).

## DƏSTƏK-ə proqram-daxili cavab (admin) — Telegram-a ehtiyac yoxdur

Admin hesabı ilə daxil olanda "DƏSTƏK" düyməsi fərqli davranır: adi müştəri kimi öz şəxsi söhbətini AÇMIR, bunun əvəzinə **bütün müştərilərin** yazışmasını göstərən bir pəncərə açır (`AdminChatWindow`, `main.py`) — sol tərəfdə yazışması olan müştərilərin siyahısı (🔴 = son sual hələ cavabsızdır, ✓ = cavablandırılıb), sağ tərəfdə seçilən müştəri ilə tam tarixçə + cavab yazma sahəsi. Cavab birbaşa `chat_messages` cədvəlinə (`direction='out'`) yazılır — bu, TAM EYNİ axındır ki, Telegram-dan sadə mətn cavabı yazanda da işlədilir (bax "Uzaqdan idarəetmə" bölməsi), ona görə müştərinin öz "DƏSTƏK" pəncərəsi cavabı adi qaydada görür, heç bir əlavə iş lazım deyil. "Cavabsız" statusu belə hesablanır: son `in` (müştəridən) mesajdan sonra heç bir `out` (operatordan) mesaj yoxdursa.

## Giriş ekranında "Ayarlar" gizlidir

"Ayarlar" düyməsi indi YALNIZ daxil olunduqdan SONRA görünür — hələ login edilməmiş halda (giriş ekranında) heç göstərilmir. Server ünvanını dəyişmək demək olar ki, heç lazım olmur (build zamanı `DEFAULT_AUTH_SERVER_URL`-ə sabitlənir), ona görə müştəri hələ daxil olmamış bunu görməyə ehtiyacı yoxdur.

## Ekran paylaşımı — AnyDesk/TeamViewer əvəzinə, RELAY ÜZƏRİNDƏN (Radmin VPN-siz)

Windows RDP (client nəşrləri) HƏMİŞƏ ayrıca sessiya yaradır — müştərinin canlı masaüstünü "güzgüləmək" mümkün deyil (bax aşağıda köhnə "Uzaqdan giriş (RDP)" bölməsi, hazırda UI-dan istifadə OLUNMUR). Bunun əvəzinə `screen_share.py` CANLI ekranı tutub JPEG kimi göndərir, uzaqdan gələn siçan/klaviaturanı `SendInput()` ilə inject edir — bu, `input_guard.py`-ın "injected input keçir" mexanizmi ilə TƏBİİ uzlaşır (AnyDesk-in tutduğu rolu tutur).

**Şəbəkə modeli (YENİ — Radmin VPN silinəndən sonra):** əvvəllər operator birbaşa müştərinin Radmin VPN IP-sinə qoşulurdu (bu, Radmin-in verdiyi NAT-aşırmadan asılı idi). İndi HƏR İKİ tərəf (müştəri VƏ operator) yalnız mərkəzi serverin `/relay` ucuna (WebSocket üzərindən, `ws_lite.py` — əl ilə yazılmış minimal RFC 6455, əlavə asılılıq YOXDUR) ÇIXIŞ bağlantısı qurur — bu, hər ikisi öz ev router-inin arxasında olsa belə HƏMİŞƏ işləyir. Server iki tərəfi eyni `(token, channel)` ilə cütləşdirib aralarında kor bayt ötürməsi aparır (`server/relay.py`). Hər kanal (FRAMES/INPUT/FILE) AYRI relay bağlantısıdır.

Qoşulma TeamViewer-tərzi ID+Kod ilə işləyir, YALNIZ Telegram-a etibar ETMİR:

1. Müştəri login edəndə client öz ID-sini (username) və təsadüfi 6 rəqəmli Kodu (`_refresh_connect_code`, hər login-də YENİLƏNİR) ekranda göstərir və `/api/connect-code/set` ilə serverə qeyd etdirir (`connect_codes` cədvəli, `CONNECT_CODE_TTL`=15 dəq etibarlıdır).
2. Müştəri bu ID+Kodu operatora telefon/DƏSTƏK çatı ilə deyir.
3. Operator ƏSAS SƏHIFƏDƏ (yalnız admin hesabında görünür) "🔗 ID + Kod ilə qoşul"-a vurub bunları yazır → client `/api/screen-share/connect-by-code` çağırır (admin-only, kodu doğrulayır). Server BURADA (`do_connect_by_code`) TƏSADÜFİ token yaradır, `screen_share_sessions`-ə yazır (relay-in "bu token mənimdir" deyə tanıması üçün) VƏ `commands` cədvəli ilə müştəriyə `start_screen_share` komandası göndərir (arg=token) VƏ token-i operatora CAVABDA DƏRHAL qaytarır.
4. Müştərinin client-i (`commands_poll`) komandanı alıb **YALNIZ** ekran-paylaşımını başladır (`_start_screen_share(token=...)`) — **EKRANI QARALTMIR**. Qaraltma tamamilə ayrıca, müstəqil əməliyyatdır. Hər kanal üçün AYRI-AYRI `/relay`-ə çıxış WS bağlantısı açılır.
5. Operatorun client-i token-i DƏRHAL aldığı üçün pollamaya EHTİYAC YOXDUR — birbaşa öz relay bağlantılarını açır (`ScreenShareViewerWindow`). Relay-in özü (`server/relay.py`, `SLOT_TIMEOUT`=60 saniyə) qarşı tərəfi (müştərini) gözləyir — bu, "hazırlıq" siqnalı rolunu oynayır.
6. İzləyici pəncərə bağlananda (`ScreenShareViewerWindow.close`) client `/api/screen-share/stop-remote` çağırır → müştəriyə uzaqdan `stop_screen_share` komandası gedir → host-un boş yerə işə davam etməsinin qarşısı alınır.

Əlavə qeydlər:
- **UAC/firewall qaydası artıq LAZIM DEYİL** — host artıq HEÇ BİR gələn bağlantı qəbul etmir (yalnız çıxış), Windows Firewall-a toxunmağa ehtiyac yoxdur.
- Bağlantı kəsiləndə (relay hop-u/server deploy-u səbəbindən) seans TAM DAĞILIR — davam etdirmə (resume) YOXDUR, yenidən qoşulmaq YENİ token tələb edir. `_receive_input` bağlantı kəsiləndə basılı qalan düymə/siçan düyməsini avtomatik buraxır (watchdog).
- Token TƏK giriş sərhədidir (fiziki Radmin VPN üzvlüyü örtülü qat artıq yoxdur) — `/relay` handshake-dən ƏVVƏL token-i `screen_share_sessions`-də DB-yə qarşı yoxlayır (bax `screen_share_token_is_valid`), həm də `X-Api-Key` tələb edir.
- "Başlat" düyməsi (yerli blackout) də bonus olaraq ekran-paylaşımını başladır (əlaqəli, amma ID+Kod axınına ehtiyac yoxdur) — bu halda müştəri TOKEN-i ÖZÜ yaradır və `/api/screen-share/notify` ilə serverə qeyd etdirir (operator `/api/screen-share/session` ilə pollayır).
- ID+Kod ekranda görünəndə hər ikisinə ayrı-ayrı vurmaqla mübadilə buferinə köçürülür (yalnız o dəyər, qarışıq deyil) — operatora ötürmək asanlaşır.
- Ctrl+Alt+Del SendInput ilə HEÇ VAXT simulyasiya edilə BİLMƏZ (Windows-un öz qoruması) — sahibin nəzarəti həmişə qalır.

### Render.com-da yerləşdirmə (auth server + relay, EYNİ prosesdə)

`server/auth_server.py` indi HƏM adi REST API-ni, HƏM `/relay` WS ucunu EYNİ portda verir (Render yalnız BİR `$PORT`-u ictimailəşdirir). Yerləşdirmə addımları:

1. `server/` qovluğunu (auth_server.py, relay.py, ws_lite.py və s.) ayrıca bir GitHub reposuna köçürün, Render-də "Web Service" olaraq bağlayın.
2. Render Environment dəyişənləri: `CSG_HOST=0.0.0.0`, `CSG_API_KEY`, `CSG_TG_TOKEN` (Telegram istifadə olunursa) — `PORT`-u Render ÖZÜ verir, koddakı `PORT = int(os.getenv("CSG_PORT", os.getenv("PORT", "8777")))` bunu avtomatik tanıyır.
3. **Ödənişli (Starter+) plan tövsiyə olunur** — pulsuz plan 15 dəq hərəkətsizlikdən sonra "yatır" (~1 dəq oyanma), canlı relay bağlantılarını da öldürür; daimi işləyən dəstək aləti üçün yararsızdır.
4. **Persistent Disk qoşun** (SQLite üçün, YALNIZ ödənişli planda mövcuddur) — `CSG_DB`-ni disk yoluna göstərin, `CSG_BACKUP_DIR`-i də (defolt `CSG_DB`-nin qovluğu) EYNİ diskə düşməsini təmin edin, əks halda backup-lar hər deploy-da itər (konteyner fayl sistemi ephemeral-dır).
5. **QEYD**: Disk qoşulmuş xidmət "sıfır-kəsilməsiz deploy" DƏSTƏKLƏMİR — hər deploy bütün canlı relay bağlantılarını (o cümlədən davam edən ekran-paylaşımı seanslarını) kəsir. Deploy-ları iş saatlarından kənara planlaşdırın.
6. `main.py`-də `DEFAULT_AUTH_SERVER_URL`-i Render-in verdiyi `https://...onrender.com` (və ya öz domeninizə) dəyişin, EXE-ni yenidən qurun, müştərilərə paylayın (bax "Versiya idarəsi" bölməsi — məcburi avtomatik yeniləmə bunu asanlaşdırır, AMMA köhnə server ünvanına bağlı köhnə exe-lər YENİ ünvanı tapmaq üçün köhnə serverin bir müddət canlı qalmasına ehtiyac duyacaq).

### Fayl köçürmə (operator → müştəri)

İzləyici pəncərədə "📁 Fayl göndər" düyməsi — ayrıca TCP kanal (`FILE` rolu) üzərindən, canlı ekran axınını KƏSMƏDƏN göndərir. Müştəri tərəfində `~\Desktop\TexnikiEkran_Alinan_Fayllar\`-a yazılır. Fayl adı `os.path.basename()` ilə TƏMİZLƏNİR (yol-keçmə/path-traversal hücumunun qarşısı alınıb), eyni adlı fayl varsa "(1)", "(2)" ... əlavə edilir, ölçü `MAX_FILE_SIZE`=300MB ilə məhdudlaşdırılıb.

### Seans qeydiyyatı (mübahisə hallarında sübut)

`ScreenShareHost.start()` ekran-paylaşımı ilə paralel, hər `RECORD_INTERVAL`=15 saniyədə bir screenshot çəkib müştərinin `~\Documents\TexnikiEkran_Qeydler\<tarix-vaxt>\` qovluğuna yazır. Son `RECORD_RETENTION_SESSIONS`=30 seans saxlanılır, köhnələr avtomatik silinir.

### Mübadilə buferi sinxronu (operator → müştəri, avtomatik)

İzləyici pəncərə açıq olduqda hər 1.5 saniyədə operatorun mübadilə buferini yoxlayır; dəyişiklik aşkarlananda `INPUT` kanalı ilə (`{"type":"clipboard","text":...}`) müştəriyə göndərir, host bunu Win32 clipboard API-ilə (`OpenClipboard`/`SetClipboardData`) öz mübadilə buferinə yazır.

### "Əlaqəni yoxla" (müştəri özü, operatora ehtiyac olmadan)

Əsas səhifədə, giriş edildikdən sonra — YALNIZ 2 şey yoxlanılır (relay memarlığında IP/firewall/port artıq mövcud deyil): (1) mərkəzi serverə HTTPS əlçatanlıq (`self.auth.health()`), (2) `/relay` ucuna REAL WS handshake — özü-üçün bir dəfəlik qeydə alınmış test token ilə (`notify_screen_share_start` + `connect_relay_channel` + dərhal bağlama + `notify_screen_share_stop`). Qeyd: bu, YALNIZ bu kompüterin öz internet əlçatanlığını göstərir, real dəstək seansının uğurunu 100% zəmanət etmir.

### Tək nüsxə qıfılı (single-instance lock)

Client eyni kompüterdə eyni anda YALNIZ BİR nüsxədə işləyə bilər (Windows adlı mutex — `CreateMutexW`, ad: `TexnikiEkran_SingleInstance_Mutex`). Proqram açılanda mutex-i yoxlayır; artıq başqa nüsxə işləyirsə xəbərdarlıq pəncərəsi göstərib dərhal bağlanır (`sys.exit(0)`), əsas UI heç yaranmır. Bu, eyni kompüterdə fərqli hesablarla və ya təsadüfən neçə dəfə açılmanın qarışıqlıq yaratmasının qarşısını alır. Mutex handle proses ömrü boyu saxlanılır (əl ilə bağlanmır) — proses bağlananda Windows onu avtomatik buraxır, növbəti açılış normal işləyir.

### Tema (ağ/qara) — avtomatik (sistem + saat ehtiyat) + əl ilə override

Proqram AÇILANDA temanı belə seçir: əvvəlcə saxlanılmış **əl ilə seçim** varsa (aşağıya bax) onu işlədir; yoxdursa, Windows-un öz rəng rejimini oxuyur (`HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme` registry açarı — Ayarlar → Fərdiləşdirmə → Rənglər); bu açar da yoxdursa/oxuna bilmirsə, saata görə qərar verir: 07:00–19:00 arası = ağ (gündüz), qalanı = qara (gecə).

**Əl ilə override:** Dil seçimi yanında (əsas pəncərənin ən altında) kiçik qara/ağ iki qutucuq var — birinə vuranda tema DƏRHAL dəyişir (əsas pəncərə canlı yenilənir) və seçim `theme_override` ayarına yazılır (`db.set_setting`), növbəti bütün açılışlarda da bu seçim davam edir (avtomatik aşkarlamadan üstündür). QEYD: canlı yeniləmə YALNIZ əsas pəncərəni əhatə edir — o anda AÇIQ olan digər pəncərələr (DƏSTƏK, Admin Panel və s.) köhnə rəngdə qalır, YENİDƏN açılanda yeni temanı götürür.

Kod tərəfi: `main.py`-də `THEME_LIGHT`/`THEME_DARK` iki ayrı palitra, `_detect_theme_mode()` avtomatik seçimi edir, `App._set_theme()`/`_apply_theme_live()` əl ilə keçidi idarə edir (bütün pəncərələr `THEME["..."]` oxuyur — kodda başqa heç nə dəyişmir).

## Uzaqdan giriş (RDP) — köhnə üsul, hazırda UI-dan çağırılmır

Ayrıca, az-hüquqlu "TexnikiEkranDestek" hesabı yaradıb Windows Remote Desktop-u YALNIZ Radmin şəbəkəsi üçün açan alternativ (bax `remote_access.py`) hələ də kodda mövcuddur, sadəcə RDP-nin "ayrıca sessiya" məhdudiyyəti səbəbindən əsas iş axınından çıxarılıb. Server bu prosesdə heç bir parol/hesab MƏLUMATI SAXLAMIR — sadəcə `/api/remote-access/notify` ilə gələn məlumatı ötürür. Müştərinin öz Windows hesabına/parolna HEÇ TOXUNULMUR.

## API açarı (kənar sorğu qoruması)

- Açar: `server/api_key.txt` (və ya `CSG_API_KEY` env). Boş buraxsan qoruma söndürülür.
- Client (`main.py` → `API_KEY`) **eyni** açarı göndərməlidir (`X-Api-Key`). Uyğun gəlməzsə server 403 qaytarır (`/api/health` istisnadır).
- Qeyd: açar EXE-də olduğu üçün "yumşaq" qorumadır — **HTTPS ilə** güclü olur.

## Uzaqdan idarəetmə (Telegram komandaları)

Operator öz Telegram-ında bota yazır:

| Komanda | Nəticə |
|---|---|
| `/lock <istifadəçi>` | Həmin müştərinin ekranını uzaqdan bağlayır |
| `/unlock <istifadəçi>` | Ekranı açır |
| `/say <istifadəçi> <mətn>` | Qara ekranda canlı təlimat göstərir |
| (müştəri mesajına **REPLY**) | İstifadəçi adı avtomatik seçilir; adi cavab müştəri chat-ına gedir |

Müştəri qoşulanda operatora avtomatik `🟢 <istifadəçi> onlayn oldu` bildirişi gəlir.

Təhlükəsizlik: uzaqdan `lock` audit log-a yazılır (`blackout_remote`), təhlükəsizlik timeout-u qüvvədədir və Ctrl+Alt+Del həmişə işləyir.

Admin əməliyyatları üçün `Authorization: Bearer <token>` başlığı lazımdır.

## Təhlükəsizlik

- Parollar PBKDF2-HMAC-SHA256 (200k iterasiya) ilə hash-lənir — açıq mətndə saxlanmır.
- Server tərəfində brute-force lockout: 5 yanlış cəhddən sonra hesab 5 dəqiqə kilidlənir.
- Parol siyasəti: ən azı 8 simvol, hərf + rəqəm.
- Yeganə admin silinə/deaktiv edilə bilməz; admin öz hesabını silə bilməz.
